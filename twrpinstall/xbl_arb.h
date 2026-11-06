//
// SPDX-FileCopyrightText: The LineageOS Project
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <string>

bool XblConfigArbAllowsSwitch(const std::string& booted_suffix, const std::string& target_suffix,
                              std::string* reason);
