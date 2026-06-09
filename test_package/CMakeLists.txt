cmake_minimum_required(VERSION 3.15)
project(test_package C)

find_package(kyber-pqc REQUIRED CONFIG)

add_executable(test_package src/test_package.c)
target_link_libraries(test_package PRIVATE kyber-pqc::kyber_pqc)
