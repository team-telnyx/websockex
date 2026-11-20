defmodule WebSockex.ConnAttemptsTest do
  use ExUnit.Case, async: true

  alias WebSockex.{Conn, ConnError}

  @loopback {127, 0, 0, 1}
  # Linux: 127.0.0.2 is loopback, so a listener with a full accept queue makes
  # it drop SYNs. macOS: the address is not assigned and SYNs to it vanish.
  @blackhole {127, 0, 0, 2}
  @slack 250

  @priv Path.join([__DIR__, "..", "support", "priv"])
  @cacertfile Path.join(@priv, "websockexca.cer")

  defmodule Client do
    use WebSockex
  end

  setup do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, ip: @loopback, active: false])
    {:ok, port} = :inet.port(listener)
    [listener: listener, port: port]
  end

  defp blackhole(port) do
    held = fill_accept_queue(:gen_tcp.listen(port, ip: @blackhole, backlog: 0), port)
    assert {:error, :timeout} = :gen_tcp.connect(@blackhole, port, [], 100)
    held
  end

  defp fill_accept_queue({:error, :eaddrnotavail}, _port), do: []

  defp fill_accept_queue({:ok, listener}, port) do
    held =
      Enum.reduce_while(1..16, [], fn _, held ->
        case :gen_tcp.connect(@blackhole, port, [], 100) do
          {:ok, socket} -> {:cont, [socket | held]}
          {:error, :timeout} -> {:halt, held}
        end
      end)

    [listener | held]
  end

  defp resolver(addresses), do: fn ~c"test.host" -> {:ok, addresses} end

  defp recorder do
    pid = self()
    fn event -> send(pid, {:attempt, event}) end
  end

  defp events do
    receive do
      {:attempt, event} -> [event | events()]
    after
      0 -> []
    end
  end

  # Timers can fire a fraction of a millisecond early.
  defp assert_about(ms, expected), do: assert(ms in (expected - 5)..(expected + @slack))

  defp timed_open(conn) do
    {us, result} = :timer.tc(fn -> Conn.open_socket(conn) end)
    {div(us, 1000), result}
  end

  defp start_tls_server do
    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        ip: @loopback,
        active: false,
        certfile: Path.join(@priv, "websockex.cer"),
        keyfile: Path.join(@priv, "websockex.key")
      )

    {:ok, {_, port}} = :ssl.sockname(listener)
    pid = self()
    spawn_link(fn -> tls_accept_loop(listener, pid) end)
    port
  end

  defp tls_accept_loop(listener, pid) do
    {:ok, socket} = :ssl.transport_accept(listener)

    with {:ok, socket} <- :ssl.handshake(socket, 2000),
         {:ok, info} <- :ssl.connection_information(socket, [:sni_hostname]) do
      send(pid, {:tls_server, Keyword.get(info, :sni_hostname)})
    end

    tls_accept_loop(listener, pid)
  end

  defp verified(port, host, opts) do
    Conn.new(
      "wss://#{host}:#{port}/",
      [tcp_attempt_timeout: 500, socket_connect_timeout: 2000] ++ opts
    )
  end

  defp cacerts, do: WebSockex.TestServer.cacerts()

  describe "tcp_attempt_timeout: nil" do
    test "keeps the single-call connect", %{port: port} do
      conn = Conn.new("ws://127.0.0.1:#{port}/", on_connect_attempt: recorder())

      assert conn.tcp_attempt_timeout == nil
      assert conn.tcp_max_attempts == 3
      assert {:ok, %Conn{socket: socket}} = Conn.open_socket(conn)
      assert is_port(socket)
      assert events() == []
    end
  end

  describe "TCP attempts" do
    test "connects on attempt 2 when the first address is black-holed", %{port: port} do
      _held = blackhole(port)

      conn =
        Conn.new("ws://test.host:#{port}/",
          tcp_attempt_timeout: 200,
          socket_connect_timeout: 2000,
          resolver: resolver([@blackhole, @loopback]),
          on_connect_attempt: recorder()
        )

      assert {elapsed, {:ok, %Conn{socket: socket}}} = timed_open(conn)
      assert_about(elapsed, 200)
      assert {:ok, {@loopback, ^port}} = :inet.peername(socket)

      assert [
               %{
                 phase: :tcp,
                 attempt: 1,
                 address: @blackhole,
                 result: {:error, :timeout},
                 ms: ms
               },
               %{phase: :tcp, attempt: 2, address: @loopback, result: :ok}
             ] = events()

      assert_about(ms, 200)
    end

    test "rotates through the addresses and gives the last attempt the time left",
         %{port: port} do
      _held = blackhole(port)

      conn =
        Conn.new("ws://test.host:#{port}/",
          tcp_attempt_timeout: 100,
          socket_connect_timeout: 600,
          resolver: resolver([@blackhole]),
          on_connect_attempt: recorder()
        )

      assert {elapsed, {:error, %ConnError{original: :timeout}}} = timed_open(conn)
      assert_about(elapsed, 600)

      assert [
               %{attempt: 1, address: @blackhole, result: {:error, :timeout}, ms: first},
               %{attempt: 2, address: @blackhole, result: {:error, :timeout}, ms: second},
               %{attempt: 3, address: @blackhole, result: {:error, :timeout}, ms: last}
             ] = events()

      assert_about(first, 100)
      assert_about(second, 100)
      assert last >= 250
    end

    test "tcp_max_attempts: 1 gives the only attempt the whole deadline", %{port: port} do
      _held = blackhole(port)

      conn =
        Conn.new("ws://test.host:#{port}/",
          tcp_attempt_timeout: 50,
          tcp_max_attempts: 1,
          socket_connect_timeout: 300,
          resolver: resolver([@blackhole, @loopback]),
          on_connect_attempt: recorder()
        )

      assert {elapsed, {:error, %ConnError{original: :timeout}}} = timed_open(conn)
      assert_about(elapsed, 300)
      assert [%{attempt: 1, ms: ms}] = events()
      assert_about(ms, 300)
    end

    test "retries a refused connect and returns the last error", %{listener: listener, port: port} do
      :ok = :gen_tcp.close(listener)

      conn =
        Conn.new("ws://127.0.0.1:#{port}/",
          tcp_attempt_timeout: 200,
          tcp_max_attempts: nil,
          on_connect_attempt: recorder()
        )

      assert {:error, %ConnError{original: :econnrefused}} = Conn.open_socket(conn)

      assert [
               %{attempt: 1, result: error},
               %{attempt: 2, result: error},
               %{attempt: 3, result: error}
             ] =
               events()

      assert error == {:error, :econnrefused}
    end

    test "does not retry other errors", %{port: port} do
      # Binding to an address that is not local fails with :eaddrnotavail.
      conn =
        Conn.new("ws://127.0.0.1:#{port}/",
          tcp_attempt_timeout: 200,
          socket_options: [ip: {192, 0, 2, 1}],
          on_connect_attempt: recorder()
        )

      assert {:error, %ConnError{original: :eaddrnotavail}} = Conn.open_socket(conn)
      assert [%{attempt: 1, result: {:error, :eaddrnotavail}}] = events()
    end

    test "socket_connect_timeout: :infinity leaves only the attempt timeout", %{port: port} do
      _held = blackhole(port)

      conn =
        Conn.new("ws://test.host:#{port}/",
          tcp_attempt_timeout: 100,
          socket_connect_timeout: :infinity,
          resolver: resolver([@blackhole, @loopback]),
          on_connect_attempt: recorder()
        )

      assert {:ok, %Conn{}} = Conn.open_socket(conn)
      assert [%{attempt: 1, result: {:error, :timeout}}, %{attempt: 2, result: :ok}] = events()
    end

    test "an IP literal skips resolution", %{port: port} do
      conn =
        Conn.new("ws://127.0.0.1:#{port}/",
          tcp_attempt_timeout: 200,
          resolver: fn _ -> raise "must not resolve" end
        )

      assert {:ok, %Conn{}} = Conn.open_socket(conn)
    end

    test "a resolution error is returned without a TCP attempt", %{port: port} do
      conn =
        Conn.new("ws://test.host:#{port}/",
          tcp_attempt_timeout: 200,
          resolver: fn _ -> {:error, :nxdomain} end,
          on_connect_attempt: recorder()
        )

      assert {:error, %ConnError{original: :nxdomain}} = Conn.open_socket(conn)
      assert events() == []
    end

    test "the deadline bounds a slow resolution", %{port: port} do
      conn =
        Conn.new("ws://test.host:#{port}/",
          tcp_attempt_timeout: 100,
          socket_connect_timeout: 200,
          resolver: fn _ -> Process.sleep(5000) end,
          on_connect_attempt: recorder()
        )

      assert {elapsed, {:error, %ConnError{original: :timeout}}} = timed_open(conn)
      assert_about(elapsed, 200)
      assert events() == []
    end

    test "a failing on_connect_attempt does not break the connect", %{port: port} do
      for fun <- [fn _ -> raise "boom" end, fn _ -> throw(:boom) end, fn _ -> exit(:boom) end] do
        conn =
          Conn.new("ws://127.0.0.1:#{port}/", tcp_attempt_timeout: 200, on_connect_attempt: fun)

        assert {:ok, %Conn{}} = Conn.open_socket(conn)
      end
    end
  end

  describe "TLS on the connected socket" do
    setup do
      [tls_port: start_tls_server()]
    end

    test "verifies the peer against the host name and sends it as SNI", %{tls_port: port} do
      conn =
        verified(port, "localhost",
          insecure: false,
          cacerts: cacerts(),
          on_connect_attempt: recorder()
        )

      assert {:ok, %Conn{conn_mod: :ssl, socket: socket}} = Conn.open_socket(conn)
      assert {:ok, {@loopback, ^port}} = :ssl.peername(socket)
      assert_receive {:tls_server, ~c"localhost"}

      assert [
               %{phase: :tcp, attempt: 1, address: @loopback, result: :ok},
               %{phase: :tls, attempt: 1, address: @loopback, result: :ok}
             ] = events()
    end

    test "connects with the insecure flag", %{tls_port: port} do
      assert {:ok, %Conn{}} = Conn.open_socket(verified(port, "localhost", insecure: true))
      assert_receive {:tls_server, ~c"localhost"}
    end

    @tag :capture_log
    test "rejects a host name that does not match the certificate", %{tls_port: port} do
      conn =
        verified(port, "test.host",
          insecure: false,
          cacerts: cacerts(),
          resolver: resolver([@loopback]),
          on_connect_attempt: recorder()
        )

      assert {:error, %ConnError{original: {:tls_alert, _}}} =
               Conn.open_socket(conn)

      assert [%{phase: :tcp, result: :ok}, %{phase: :tls, result: {:error, {:tls_alert, _}}}] =
               events()
    end

    @tag :capture_log
    test "rejects an IP literal like the single-call connect does", %{tls_port: port} do
      opts = [insecure: false, cacerts: cacerts()]
      single_call = Conn.new("wss://127.0.0.1:#{port}/", opts)

      assert {:error, %ConnError{original: {:tls_alert, _}}} =
               Conn.open_socket(single_call)

      assert {:error, %ConnError{original: {:tls_alert, _}}} =
               Conn.open_socket(verified(port, "127.0.0.1", opts))
    end

    test "honours the caller's ssl_options", %{tls_port: port} do
      pid = self()

      verify_fun = fn
        _cert, {:bad_cert, reason}, state ->
          {:fail, {reason, state}}

        _cert, {:extension, _}, state ->
          {:unknown, state}

        _cert, event, state ->
          send(pid, {:verify_fun, event})
          {:valid, state}
      end

      ssl_options = [verify: :verify_peer, cacertfile: @cacertfile, verify_fun: {verify_fun, []}]

      assert {:ok, %Conn{ssl_options: ^ssl_options}} =
               Conn.open_socket(verified(port, "localhost", ssl_options: ssl_options))

      assert_receive {:verify_fun, :valid_peer}
      assert_receive {:tls_server, ~c"localhost"}
    end

    test "keeps the caller's server_name_indication", %{tls_port: port} do
      ssl_options = [verify: :verify_none, server_name_indication: ~c"other.example"]

      assert {:ok, %Conn{}} =
               Conn.open_socket(verified(port, "localhost", ssl_options: ssl_options))

      assert_receive {:tls_server, ~c"other.example"}
    end

    test "keeps the caller's customize_hostname_check", %{tls_port: port} do
      ssl_options = [
        verify: :verify_peer,
        cacertfile: @cacertfile,
        customize_hostname_check: [match_fun: fn _reference, _presented -> true end]
      ]

      conn =
        verified(port, "test.host", ssl_options: ssl_options, resolver: resolver([@loopback]))

      assert {:ok, %Conn{}} = Conn.open_socket(conn)
      assert_receive {:tls_server, ~c"test.host"}
    end

    test "the deadline bounds the handshake and the TCP socket is closed on failure",
         %{listener: listener, port: port} do
      # A plain TCP listener: accepts the connection, never answers the ClientHello.
      conn =
        Conn.new("wss://127.0.0.1:#{port}/",
          tcp_attempt_timeout: 100,
          socket_connect_timeout: 300,
          on_connect_attempt: recorder()
        )

      assert {elapsed, {:error, %ConnError{original: :timeout}}} = timed_open(conn)
      assert_about(elapsed, 300)

      assert [%{phase: :tcp, result: :ok}, %{phase: :tls, result: {:error, :timeout}}] = events()

      {:ok, accepted} = :gen_tcp.accept(listener, 500)
      assert recv_until_closed(accepted) == :closed
    end
  end

  describe "TLS failure before the handshake starts" do
    test "closes the TCP socket", %{listener: listener, port: port} do
      conn =
        Conn.new("wss://127.0.0.1:#{port}/",
          tcp_attempt_timeout: 200,
          ssl_options: [verify: :not_a_verify_type]
        )

      assert {:error, %ConnError{original: {:options, _}}} = Conn.open_socket(conn)

      {:ok, accepted} = :gen_tcp.accept(listener, 500)
      assert :gen_tcp.recv(accepted, 0, 500) == {:error, :closed}
    end
  end

  describe "upgrade timeout" do
    for opts <- [[], [tcp_attempt_timeout: 200]] do
      test "returns :upgrade_timeout with #{inspect(opts)}", %{port: port} do
        # The listener accepts the connection and never answers the request.
        opts = [socket_recv_timeout: 100] ++ unquote(opts)
        {:ok, conn} = Conn.new("ws://127.0.0.1:#{port}/", opts) |> Conn.open_socket()
        {:ok, request} = Conn.build_request(conn, "pants")
        :ok = Conn.socket_send(conn, request)

        assert Conn.handle_response(conn, self()) ==
                 {:error, %ConnError{original: :upgrade_timeout}}
      end
    end
  end

  describe "WebSockex.start_link/4 with tcp_attempt_timeout" do
    test "connects over ws" do
      {:ok, {server_ref, url}} = WebSockex.TestServer.start(self())
      on_exit(fn -> WebSockex.TestServer.shutdown(server_ref) end)

      assert {:ok, pid} =
               WebSockex.start(url, Client, nil,
                 tcp_attempt_timeout: 500,
                 on_connect_attempt: recorder()
               )

      assert is_pid(WebSockex.TestServer.receive_socket_pid())
      assert_receive {:attempt, %{phase: :tcp, attempt: 1, result: :ok}}
      Process.exit(pid, :kill)
    end

    test "connects over wss" do
      {:ok, {server_ref, url}} = WebSockex.TestServer.start_https(self())
      on_exit(fn -> WebSockex.TestServer.shutdown(server_ref) end)

      assert {:ok, pid} =
               WebSockex.start(url, Client, nil,
                 tcp_attempt_timeout: 500,
                 insecure: false,
                 cacerts: cacerts(),
                 on_connect_attempt: recorder()
               )

      assert is_pid(WebSockex.TestServer.receive_socket_pid())
      assert_receive {:attempt, %{phase: :tls, attempt: 1, result: :ok}}
      Process.exit(pid, :kill)
    end
  end

  defp recv_until_closed(socket) do
    case :gen_tcp.recv(socket, 0, 1000) do
      {:ok, _data} -> recv_until_closed(socket)
      {:error, reason} -> reason
    end
  end
end
