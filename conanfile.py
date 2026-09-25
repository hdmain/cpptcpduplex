from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout


class CpptcpduplexConan(ConanFile):
    name = "cpptcpduplex"
    version = "1.0.0"
    package_type = "library"
    license = "SEE LICENSE.md"
    url = "https://github.com/hdmain/cpptcpduplex"
    description = "Native C++20 encrypted full-duplex TCP (X25519 + AES-256-GCM)"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "include/*",
        "src/*",
        "third_party/*",
        "LICENSE.md",
        "README.md",
    )

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["CPPTCPDUPLEX_BUILD_SHARED"] = self.options.shared
        tc.variables["CPPTCPDUPLEX_BUILD_TESTS"] = False
        tc.variables["CPPTCPDUPLEX_BUILD_EXAMPLES"] = False
        tc.variables["CPPTCPDUPLEX_ENABLE_INSTALL"] = True
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "cpptcpduplex")
        self.cpp_info.set_property("cmake_target_name", "cpptcpduplex::cpptcpduplex")
        self.cpp_info.libs = ["cpptcpduplex", "mbedcrypto"]
        if self.settings.os == "Windows":
            self.cpp_info.system_libs = ["ws2_32"]
