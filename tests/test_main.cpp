#include <cstdlib>
#include <iostream>
#include <string>

int test_protocol();
int test_conn();
int test_transfer();

int main() {
  int failed = 0;
  failed += test_protocol();
  failed += test_conn();
  failed += test_transfer();
  if (failed == 0) {
    std::cout << "All tests passed\n";
    return 0;
  }
  std::cerr << failed << " test suite(s) failed\n";
  return 1;
}
