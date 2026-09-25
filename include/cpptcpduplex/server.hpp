#pragma once

#include "cpptcpduplex/config.hpp"
#include "cpptcpduplex/conn.hpp"
#include "cpptcpduplex/detail/socket.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace cpptcpduplex {

class Server {
 public:
  Server(std::unique_ptr<detail::TcpListener> ln, Config cfg);
  ~Server();

  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  static std::unique_ptr<Server> listen(const std::string& network, const std::string& addr,
                                        const Config* cfg = nullptr);
  static std::unique_ptr<Server> listen(const std::string& network, const std::string& addr,
                                        const Config* cfg, std::error_code& ec);

  std::string addr() const;
  void close();

  // Accepts connections until stop() / close() or Accept fails.
  // on_connect is invoked on a worker thread per peer after handshake.
  using OnConnect = std::function<void(Conn&)>;
  void serve(OnConnect on_connect);
  void serve(OnConnect on_connect, std::error_code& ec);
  void stop();

 private:
  Config cfg_;
  std::unique_ptr<detail::TcpListener> ln_;
  std::atomic<bool> stopping_{false};
  std::mutex workers_mu_;
  std::vector<std::thread> workers_;
};

}  // namespace cpptcpduplex
