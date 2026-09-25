#pragma once

#include "cpptcpduplex/config.hpp"
#include "cpptcpduplex/conn.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace cpptcpduplex {

// Dial TCP, negotiate tcpduplex, and return a running Conn.
std::unique_ptr<Conn> dial(const std::string& address);
std::unique_ptr<Conn> dial(const std::string& address, const Config* cfg);
std::unique_ptr<Conn> dial(const std::string& address, const Config* cfg, std::error_code& ec);
std::unique_ptr<Conn> dial_for(const std::string& address, const Config* cfg,
                               std::chrono::milliseconds overall_timeout, std::error_code& ec);

// Complete the listener handshake on an accepted TCP socket (takes ownership of fd).
std::unique_ptr<Conn> serve_conn(std::unique_ptr<detail::TcpSocket> sock);
std::unique_ptr<Conn> serve_conn(std::unique_ptr<detail::TcpSocket> sock, const Config* cfg);
std::unique_ptr<Conn> serve_conn(std::unique_ptr<detail::TcpSocket> sock, const Config* cfg,
                                 std::error_code& ec);
std::unique_ptr<Conn> serve_conn_for(std::unique_ptr<detail::TcpSocket> sock, const Config* cfg,
                                     std::chrono::milliseconds overall_timeout,
                                     std::error_code& ec);

}  // namespace cpptcpduplex
