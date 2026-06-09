import os
import re

from conan import ConanFile
from conan.errors import ConanException
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import copy, load


class KyberPqcConan(ConanFile):
    name = "kyber-pqc"
    license = "MIT"
    author = "Bajpai Labs <hello@bajpailabs.com>"
    url = "https://github.com/krish567366/Kyber-PQC"
    homepage = "https://quantum.postquantumlabs.in/kyber-pqc"
    description = "Native high-performance ML-KEM-512 (Kyber-512) implementation"
    topics = ("post-quantum", "cryptography", "kyber", "ml-kem", "kem")
    package_type = "library"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
    }

    def set_version(self):
        pyproject = load(
            self,
            os.path.join(self.recipe_folder, "pyproject.toml"),
        )
        match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
        if not match:
            raise ConanException("Could not read version from pyproject.toml")
        self.version = match.group(1)

    def export_sources(self):
        copy(self, "*", src=os.path.join(self.recipe_folder, "c"), dst=self.export_sources_folder)
        copy(self, "LICENSE", src=self.recipe_folder, dst=self.export_sources_folder)

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["PROJECT_VERSION"] = self.version
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        copy(
            self,
            "LICENSE",
            src=self.export_sources_folder,
            dst=os.path.join(self.package_folder, "licenses"),
        )

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "kyber-pqc")
        self.cpp_info.set_property("cmake_target_name", "kyber-pqc::kyber_pqc")
        self.cpp_info.libs = ["kyber_pqc"]
