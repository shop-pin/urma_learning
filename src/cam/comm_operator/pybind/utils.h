/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: pybind utils header file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 add pybind utils header file
 */

#pragma once

#include <c10/core/ScalarType.h>
#include <Python.h>

class TrochBindException : public std::exception
{
private:
    std::string message = {};

public:
    explicit TrochBindException(const char *name, const char *file, const int line, const std::string &error)
    {
        message = std::string("Failed: ") + name + " error " + file + ":" + std::to_string(line) +
                  " error message or error code is '" + error + "'";
    }

    const char *what() const noexcept override
    {
        return message.c_str();
    }
};

#define TORCH_BIND_ASSERT(cond)                                           \
    ;                                                                  \
    do {                                                               \
        if (not(cond)) {                                               \
            throw TrochBindException("Assertion", __FILE__, __LINE__, #cond); \
        }                                                              \
    } while (0)