cmake_minimum_required(VERSION 3.19)
project(
    task_system
    DESCRIPTION "Fiber based task system"
    LANGUAGES C
)


add_executable(task_system_test task_system_test.c task_system.h)
