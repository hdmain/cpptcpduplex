#include "cpptcpduplex/server.hpp"
#include "cpptcpduplex/dial.hpp"

namespace cpptcpduplex {

Server::Server(std::unique_ptr<detail::TcpListener> ln, Config cfg)
    : cfg_(std::move(cfg)), ln_(std::move(ln)) {}

Server::~Server() {
  stop();
  close();
  std::lock_guard lock(workers_mu_);
  for (auto& t : workers_) {
    if (t.joinable()) {
      t.join();
    }
  }
}

std::unique_ptr<Server> Server::listen(const std::string& network, const std::string& addr,
                                       const Config* cfg) {
  std::error_code ec;
  auto s = listen(network, addr, cfg, ec);
  if (ec) {
    throw Error("listen", ec);
  }
  return s;
}

std::unique_ptr<Server> Server::listen(const std::string& network, const std::string& addr,
                                       const Config* cfg, std::error_code& ec) {
  ec.clear();
  if (network != "tcp" && network != "tcp4" && network != "tcp6") {
    ec = make_error_code(errc::other);
    return nullptr;
  }
  auto ln = detail::TcpListener::listen(addr, ec);
  if (!ln) {
    return nullptr;
  }
  Config c = cfg ? *cfg : default_config();
  return std::unique_ptr<Server>(new Server(std::move(ln), std::move(c)));
}

std::string Server::addr() const { return ln_ ? ln_->addr() : std::string{}; }

void Server::close() {
  stopping_.store(true);
  if (ln_) {
    ln_->close();
  }
}

void Server::stop() { close(); }

void Server::serve(OnConnect on_connect) {
  std::error_code ec;
  serve(std::move(on_connect), ec);
  if (ec && ec != errc::closed && !stopping_.load()) {
    throw Error("serve", ec);
  }
}

void Server::serve(OnConnect on_connect, std::error_code& ec) {
  ec.clear();
  if (!on_connect) {
    ec = make_error_code(errc::other);
    return;
  }
  while (!stopping_.load()) {
    auto raw = ln_->accept(ec);
    if (!raw) {
      if (stopping_.load()) {
        ec = make_error_code(errc::canceled);
      }
      break;
    }
    std::lock_guard lock(workers_mu_);
    workers_.emplace_back([this, sock = std::move(raw), on_connect]() mutable {
      std::error_code hec;
      auto conn = serve_conn(std::move(sock), &cfg_, hec);
      if (!conn) {
        return;
      }
      on_connect(*conn);
    });
  }
  std::lock_guard lock(workers_mu_);
  for (auto& t : workers_) {
    if (t.joinable()) {
      t.join();
    }
  }
  workers_.clear();
}

}  // namespace cpptcpduplex
