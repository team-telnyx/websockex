defmodule WebSockex.Conn do
  @moduledoc """
  Handles establishing and controlling the TCP connection.

  Dispatches to the correct module for the underlying connection. (`:gen_tcp` or `:ssl`)

  Is woefully inadequite for verifying proper peers in SSL connections.

  ## Fresh-socket TCP attempts

  By default a connection is one `:gen_tcp.connect/4` or `:ssl.connect/4` call
  with `:socket_connect_timeout` as its timeout. When a TCP SYN is lost, the
  kernel retransmits it on the same socket, and that flow often stays lossy.

  Setting `:tcp_attempt_timeout` switches to a different connect path:

  1. `:socket_connect_timeout` becomes one deadline for DNS resolution, all TCP
     attempts and the TLS handshake together.
  2. The host is resolved once (IPv4, `:inet.getaddrs/2`). IP literals skip
     resolution.
  3. Up to `:tcp_max_attempts` TCP connects are made, each on a new socket (new
     source port), rotating through the resolved addresses. Each attempt waits
     `min(tcp_attempt_timeout, time left)`; the last attempt waits for all the
     time that is left. Only `:timeout`, `:econnrefused`, `:econnreset`,
     `:closed`, `:ehostunreach` and `:enetunreach` lead to another attempt.
  4. For `wss://`, the TLS handshake runs once on the connected socket with the
     time that is left. It is never retried. The host name is sent as SNI and
     used for hostname verification, as in the default path, unless
     `:ssl_options` already contains `:server_name_indication`.

  In this path `:socket_options` apply to the TCP socket for `wss://` too.
  TCP-level options inside `:ssl_options` (for example `:nodelay`) are not
  applied to the socket; put them in `:socket_options`.

  When the deadline is used up before the TLS handshake can start, the
  `:on_connect_attempt` function still gets a `:tls` event with
  `result: {:error, :timeout}`.
  """

  @socket_connect_timeout_default 6000
  @socket_recv_timeout_default 5000
  @tcp_max_attempts_default 3
  @retryable_tcp_errors [
    :timeout,
    :econnrefused,
    :econnreset,
    :closed,
    :ehostunreach,
    :enetunreach
  ]

  defstruct conn_mod: nil,
            host: nil,
            port: nil,
            path: nil,
            query: nil,
            extra_headers: [],
            transport: nil,
            socket: nil,
            socket_connect_timeout: @socket_connect_timeout_default,
            socket_recv_timeout: @socket_recv_timeout_default,
            cacerts: nil,
            insecure: true,
            resp_headers: [],
            ssl_options: nil,
            socket_options: nil,
            tcp_attempt_timeout: nil,
            tcp_max_attempts: @tcp_max_attempts_default,
            on_connect_attempt: nil,
            resolver: nil

  @type socket :: :gen_tcp.socket() | :ssl.sslsocket()
  @type header :: {field :: String.t(), value :: String.t()}
  @type transport :: :tcp | :ssl

  @type certification :: :public_key.der_encoded()

  @typedoc """
  Options used when establishing a tcp or ssl connection.

  - `:extra_headers` - defines other headers to be send in the opening request.
  - `:insecure` - Determines whether to verify the peer in a SSL connection.
    SSL peer verification is currenctly broken and only works in certain cases
    in which the `:cacerts` are also provided. Sorry. _Defaults to `true`_.
  - `:cacerts` - The CA certifications for use in an secure connection when the
    `:insecure` option is `false` (has no effect when `:insecure is true`).
    These certifications need a list of decoded binaries. See the
    [Erlang `:public_key` module][public_key] for more information.
  - `:socket_connect_timeout` - Timeout in ms for creating a TCP connection,
    default #{@socket_connect_timeout_default} ms.
  - `:socket_recv_timeout` - Timeout in ms for receiving a HTTP response header
    from socket, default #{@socket_recv_timeout_default} ms.
  - `:ssl_options` - extra options for an SSL connection
  - `:socket_options` - extra options for the TCP part of the connection
  - `:tcp_attempt_timeout` - Timeout in ms for one TCP connect attempt. Setting
    it enables fresh-socket TCP attempts and makes `:socket_connect_timeout`
    the deadline for DNS + TCP + TLS together, see the module documentation.
    _Defaults to `nil`_, which keeps the single-call connect.
  - `:tcp_max_attempts` - Maximum number of TCP connect attempts when
    `:tcp_attempt_timeout` is set, default #{@tcp_max_attempts_default}.
  - `:on_connect_attempt` - A 1-arity function called after each TCP attempt
    and after the TLS handshake when `:tcp_attempt_timeout` is set. It receives
    a `t:connect_attempt/0` map. It runs in the connecting process; anything it
    raises, throws or exits with is ignored. The time it takes counts against
    `:socket_connect_timeout`, so keep it fast.

  [public_key]: http://erlang.org/doc/apps/public_key/using_public_key.html
  """
  @type connection_option ::
          {:extra_headers, [header]}
          | {:cacerts, [certification]}
          | {:insecure, boolean}
          | {:socket_connect_timeout, non_neg_integer}
          | {:socket_recv_timeout, non_neg_integer}
          | {:ssl_options, [:ssl.tls_client_option()]}
          | {:socket_options, [:gen_tcp.option()]}
          | {:tcp_attempt_timeout, pos_integer | nil}
          | {:tcp_max_attempts, pos_integer}
          | {:on_connect_attempt, (connect_attempt -> any) | nil}

  @typedoc """
  The event passed to the `:on_connect_attempt` function.

  - `:phase` - `:tcp` for a TCP connect attempt, `:tls` for the TLS handshake.
  - `:attempt` - The TCP attempt number, starting at 1. For `:tls` it is the
    attempt that produced the socket.
  - `:address` - The IP address used.
  - `:ms` - Duration of the attempt or handshake in ms.
  - `:result` - `:ok` or `{:error, reason}`.
  """
  @type connect_attempt :: %{
          phase: :tcp | :tls,
          attempt: pos_integer,
          address: :inet.ip_address(),
          ms: non_neg_integer,
          result: :ok | {:error, term}
        }

  @type t :: %__MODULE__{
          conn_mod: :gen_tcp | :ssl,
          host: String.t(),
          port: non_neg_integer,
          path: String.t(),
          query: String.t() | nil,
          extra_headers: [header],
          transport: transport,
          socket: socket | nil,
          socket_connect_timeout: non_neg_integer,
          socket_recv_timeout: non_neg_integer,
          resp_headers: [header],
          tcp_attempt_timeout: pos_integer | nil,
          tcp_max_attempts: pos_integer,
          on_connect_attempt: (connect_attempt -> any) | nil
        }

  @doc """
  Returns a new `WebSockex.Conn` struct from a uri and options.
  """
  @spec new(url :: String.t() | URI.t(), [connection_option]) ::
          __MODULE__.t() | {:error, %WebSockex.URLError{}}
  def new(url, opts \\ [])

  def new(%URI{} = uri, opts) do
    mod = conn_module(uri.scheme)

    %WebSockex.Conn{
      host: uri.host,
      port: uri.port,
      path: uri.path,
      query: uri.query,
      conn_mod: mod,
      transport: transport(mod),
      extra_headers: Keyword.get(opts, :extra_headers, []),
      cacerts: Keyword.get(opts, :cacerts, nil),
      insecure: Keyword.get(opts, :insecure, true),
      socket_connect_timeout:
        Keyword.get(opts, :socket_connect_timeout, @socket_connect_timeout_default),
      socket_recv_timeout: Keyword.get(opts, :socket_recv_timeout, @socket_recv_timeout_default),
      ssl_options: Keyword.get(opts, :ssl_options, nil),
      socket_options: Keyword.get(opts, :socket_options, nil),
      tcp_attempt_timeout: Keyword.get(opts, :tcp_attempt_timeout, nil),
      tcp_max_attempts: Keyword.get(opts, :tcp_max_attempts) || @tcp_max_attempts_default,
      on_connect_attempt: Keyword.get(opts, :on_connect_attempt, nil),
      # Test seam: `(charlist -> {:ok, [:inet.ip_address()]} | {:error, term})`.
      resolver: Keyword.get(opts, :resolver, nil)
    }
  end

  def new(url, opts) do
    case parse_url(url) do
      {:ok, %URI{} = uri} -> new(uri, opts)
      {:error, _} = error -> error
    end
  end

  @doc """
  Parses a url string for a valid URI
  """
  @spec parse_url(String.t()) :: {:ok, URI.t()} | {:error, %WebSockex.URLError{}}
  def parse_url(url) do
    case URI.parse(url) do
      %URI{port: port, scheme: protocol} when protocol in ["ws", "wss"] and is_nil(port) ->
        # Someone may have deleted the URI config but I'm going to assume it's
        # just that the application didn't get them registered.
        {:error, %WebSockex.ApplicationError{reason: :not_started}}

      # This is confusing to look at. But it's just a match with multiple guards
      %URI{host: host, port: port, scheme: protocol}
      when is_nil(host)
      when is_nil(port)
      when protocol not in ["ws", "wss", "http", "https"] ->
        {:error, %WebSockex.URLError{url: url}}

      %URI{path: nil} = uri ->
        {:ok, %{uri | path: "/"}}

      %URI{} = uri ->
        {:ok, uri}
    end
  end

  @doc """
  Parses a URI host
  Host can be "x.y.z.t" or "some.name.domain". If "x.y.z.t", the function
  will return a valid :inet.ip_address() which __MODULE__.open_socket
  accepts. This will prevent extra DNS operations which can time out
  in some contexts
  """
  @spec parse_host(String.t()) :: charlist() | :inet.ip_address()
  def parse_host(host) do
    parsed =
      host
      |> to_charlist()
      |> :inet.parse_address()

    case parsed do
      {:error, :einval} -> to_charlist(host)
      {:ok, addr} -> addr
    end
  end

  @doc """
  Sends data using the `conn_mod` module.
  """
  @spec socket_send(__MODULE__.t(), binary) :: :ok | {:error, reason :: term}
  def socket_send(conn, message) do
    case conn.conn_mod.send(conn.socket, message) do
      :ok -> :ok
      {:error, error} -> {:error, %WebSockex.ConnError{original: error}}
    end
  end

  @doc """
  Opens a socket to a uri and returns a conn struct.
  """
  @spec open_socket(__MODULE__.t()) :: {:ok, __MODULE__.t()} | {:error, term}
  def open_socket(conn)

  def open_socket(%{tcp_attempt_timeout: timeout} = conn) when is_integer(timeout) do
    deadline = deadline(conn.socket_connect_timeout)

    with {:ok, addresses} <- resolve(conn, deadline),
         {:ok, socket, attempt, address} <- tcp_connect(conn, addresses, 1, deadline),
         {:ok, socket} <- tls_upgrade(conn, socket, attempt, address, deadline) do
      {:ok, Map.put(conn, :socket, socket)}
    else
      {:error, reason} -> {:error, %WebSockex.ConnError{original: reason}}
    end
  end

  def open_socket(%{conn_mod: :gen_tcp} = conn) do
    case :gen_tcp.connect(
           parse_host(conn.host),
           conn.port,
           socket_connection_options(conn),
           conn.socket_connect_timeout
         ) do
      {:ok, socket} ->
        {:ok, Map.put(conn, :socket, socket)}

      {:error, error} ->
        {:error, %WebSockex.ConnError{original: error}}
    end
  end

  def open_socket(%{conn_mod: :ssl} = conn) do
    case :ssl.connect(
           parse_host(conn.host),
           conn.port,
           ssl_connection_options(conn),
           conn.socket_connect_timeout
         ) do
      {:ok, socket} ->
        {:ok, Map.put(conn, :socket, socket)}

      {:error, error} ->
        {:error, %WebSockex.ConnError{original: error}}
    end
  end

  @doc """
  Closes the socket and returns the Conn map without the socket.

  When the `:socket` field is `nil` in the struct, the function just returns
  the struct as is.
  """
  @spec close_socket(__MODULE__.t()) :: %WebSockex.Conn{socket: nil}
  def close_socket(conn)
  def close_socket(%{socket: nil} = conn), do: conn

  def close_socket(%{socket: socket} = conn) do
    conn.conn_mod.close(socket)
    %{conn | socket: nil}
  end

  @doc """
  Builds the request to be sent along the newly opened socket.

  The key parameter is part of the websocket handshake process.
  """
  @spec build_request(__MODULE__.t(), key :: String.t()) :: {:ok, String.t()}
  def build_request(conn, key) do
    host =
      if conn.port in [80, 443] do
        conn.host
      else
        "#{conn.host}:#{conn.port}"
      end

    headers =
      ([
         {"Host", host},
         {"Connection", "Upgrade"},
         {"Upgrade", "websocket"},
         {"Sec-WebSocket-Version", "13"},
         {"Sec-WebSocket-Key", key}
       ] ++ conn.extra_headers)
      |> Enum.map(&format_header/1)

    # Build the request
    request =
      ["GET #{build_full_path(conn)} HTTP/1.1" | headers]
      |> Enum.join("\r\n")

    {:ok, request <> "\r\n\r\n"}
  end

  @doc """
  Waits for the request response, decodes the packet, and returns the response
  headers.

  Sends any access information in the buffer back to the process as a message
  to be processed.
  """
  @spec handle_response(__MODULE__.t(), pid()) :: {:ok, [header]} | {:error, reason :: term}
  def handle_response(conn, owner_pid) do
    with {:ok, buffer} <- wait_for_response(conn),
         {:ok, headers, buffer} <- decode_response(buffer) do
      # Send excess buffer back to the process
      if buffer != "" do
        send(owner_pid, {transport(conn.conn_mod), conn.socket, buffer})
      end

      {:ok, headers}
    end
  end

  @doc """
  Sets the socket to active.
  """
  @spec set_active(__MODULE__.t(), true | false) :: :ok | {:error, reason :: term}
  def set_active(conn, val \\ true)

  def set_active(%{conn_mod: :gen_tcp} = conn, val) do
    :inet.setopts(conn.socket, active: val)
  end

  def set_active(%{conn_mod: :ssl} = conn, val) do
    :ssl.setopts(conn.socket, active: val)
  end

  @doc """
  Set the socket's controlling process.
  """
  @spec controlling_process(__MODULE__.t(), new_owner :: pid) :: :ok | {:error, term}
  def controlling_process(conn, new_owner) do
    conn.conn_mod.controlling_process(conn.socket, new_owner)
  end

  defp transport(:gen_tcp), do: :tcp
  defp transport(:ssl), do: :ssl
  defp transport(_), do: nil

  defp conn_module("ws"), do: :gen_tcp
  defp conn_module("http"), do: :gen_tcp
  defp conn_module("wss"), do: :ssl
  defp conn_module("https"), do: :ssl
  defp conn_module(_), do: nil

  defp wait_for_response(conn, buffer \\ "") do
    case Regex.match?(~r/\r\n\r\n/, buffer) do
      true ->
        {:ok, buffer}

      false ->
        with {:ok, data} <- conn.conn_mod.recv(conn.socket, 0, conn.socket_recv_timeout) do
          wait_for_response(conn, buffer <> data)
        else
          {:error, reason} -> {:error, %WebSockex.ConnError{original: upgrade_error(reason)}}
        end
    end
  end

  # The request is already sent here, so a timeout must not look like a
  # connect timeout.
  defp upgrade_error(:timeout), do: :upgrade_timeout
  defp upgrade_error(reason), do: reason

  defp format_header({field, value}) do
    "#{field}: #{value}"
  end

  defp build_full_path(%__MODULE__{path: path, query: query}) do
    struct(URI, %{path: path, query: query})
    |> URI.to_string()
  end

  defp decode_response(response) do
    case :erlang.decode_packet(:http_bin, response, []) do
      {:ok, {:http_response, _version, 101, _message}, rest} ->
        decode_headers(rest)

      {:ok, {:http_response, _, code, message}, _} ->
        {:error, %WebSockex.RequestError{code: code, message: message}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp decode_headers(rest, headers \\ []) do
    case :erlang.decode_packet(:httph_bin, rest, []) do
      {:ok, {:http_header, _len, field, _res, value}, rest} ->
        decode_headers(rest, [{field, value} | headers])

      {:ok, :http_eoh, body} ->
        {:ok, headers, body}
    end
  end

  defp minimal_socket_connection_options() do
    [
      mode: :binary,
      active: false,
      packet: 0
    ]
  end

  defp socket_connection_options(%{socket_options: socket_options})
       when not is_nil(socket_options) do
    minimal_socket_connection_options()
    |> Keyword.merge(socket_options)
  end

  defp socket_connection_options(%{socket_options: _socket_options}) do
    minimal_socket_connection_options()
  end

  # Fresh-socket TCP attempts, then TLS once. One deadline bounds all of it.

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp deadline(:infinity), do: :infinity
  defp deadline(timeout), do: now_ms() + timeout

  defp time_left(:infinity), do: :infinity
  defp time_left(deadline), do: max(deadline - now_ms(), 0)

  defp resolve(conn, deadline) do
    case parse_host(conn.host) do
      address when is_tuple(address) -> {:ok, [address]}
      host -> resolve_host(conn.resolver || (&:inet.getaddrs(&1, :inet)), host, deadline)
    end
  end

  # `:inet.getaddrs/2` has no reliable timeout, so the deadline is enforced by
  # killing the lookup.
  defp resolve_host(resolver, host, deadline) do
    task = Task.async(fn -> resolver.(host) end)

    case Task.yield(task, time_left(deadline)) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, [_ | _] = addresses}} -> {:ok, addresses}
      {:ok, {:ok, []}} -> {:error, :nxdomain}
      {:ok, {:error, reason}} -> {:error, reason}
      nil -> {:error, :timeout}
    end
  end

  defp tcp_connect(conn, addresses, attempt, deadline) do
    case time_left(deadline) do
      0 -> {:error, :timeout}
      left -> tcp_attempt(conn, addresses, attempt, deadline, left)
    end
  end

  defp tcp_attempt(conn, addresses, attempt, deadline, left) do
    address = Enum.at(addresses, rem(attempt - 1, length(addresses)))
    timeout = tcp_timeout(conn, attempt, left)
    started = now_ms()
    result = :gen_tcp.connect(address, conn.port, socket_connection_options(conn), timeout)
    notify(conn, :tcp, attempt, address, started, result)
    after_tcp_attempt(result, address, conn, addresses, attempt, deadline)
  end

  # The last attempt gets all the time that is left.
  defp tcp_timeout(%{tcp_max_attempts: max}, attempt, left) when attempt >= max, do: left
  defp tcp_timeout(%{tcp_attempt_timeout: timeout}, _attempt, left), do: min(timeout, left)

  defp after_tcp_attempt({:ok, socket}, address, _conn, _addresses, attempt, _deadline),
    do: {:ok, socket, attempt, address}

  defp after_tcp_attempt(
         {:error, reason},
         _address,
         %{tcp_max_attempts: max} = conn,
         addresses,
         attempt,
         deadline
       )
       when reason in @retryable_tcp_errors and attempt < max,
       do: tcp_connect(conn, addresses, attempt + 1, deadline)

  defp after_tcp_attempt({:error, _} = error, _address, _conn, _addresses, _attempt, _deadline),
    do: error

  defp tls_upgrade(%{conn_mod: :gen_tcp}, socket, _attempt, _address, _deadline),
    do: {:ok, socket}

  defp tls_upgrade(conn, socket, attempt, address, deadline) do
    started = now_ms()
    result = tls_handshake(socket, upgrade_ssl_options(conn), time_left(deadline))
    notify(conn, :tls, attempt, address, started, result)
    close_on_error(result, socket)
  end

  defp tls_handshake(_socket, _options, 0), do: {:error, :timeout}
  defp tls_handshake(socket, options, left), do: :ssl.connect(socket, options, left)

  defp close_on_error({:ok, _} = ok, _socket), do: ok

  defp close_on_error({:error, _} = error, socket) do
    :gen_tcp.close(socket)
    error
  end

  # `:ssl.connect/3` on a connected socket does not know the host name. Without
  # SNI it would verify the certificate against the IP address.
  defp upgrade_ssl_options(conn) do
    conn |> ssl_connection_options() |> put_sni(parse_host(conn.host))
  end

  defp put_sni(options, address) when is_tuple(address), do: options
  defp put_sni(options, host), do: Keyword.put_new(options, :server_name_indication, host)

  defp notify(%{on_connect_attempt: fun}, phase, attempt, address, started, result)
       when is_function(fun, 1) do
    fun.(%{
      phase: phase,
      attempt: attempt,
      address: address,
      ms: now_ms() - started,
      result: attempt_result(result)
    })
  catch
    _kind, _reason -> :ok
  end

  defp notify(_conn, _phase, _attempt, _address, _started, _result), do: :ok

  defp attempt_result({:ok, _socket}), do: :ok
  defp attempt_result({:error, _} = error), do: error

  # Crazy SSL Stuff (It will be normal SSL stuff when I figure out Erlang's ssl)

  defp ssl_connection_options(%{ssl_options: ssl_options}) when not is_nil(ssl_options) do
    [
      mode: :binary,
      active: false,
      packet: 0
    ]
    |> Keyword.merge(ssl_options)
  end

  defp ssl_connection_options(%{insecure: true}) do
    [
      :binary,
      active: false,
      packet: 0,
      verify: :verify_none
    ]
  end

  defp ssl_connection_options(%{cacerts: cacerts}) when cacerts != nil do
    [
      :binary,
      active: false,
      packet: 0,
      verify: :verify_peer,
      cacerts: cacerts
    ]
  end
end
