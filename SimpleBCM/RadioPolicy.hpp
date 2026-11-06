//
//  RadioPolicy.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/6.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_RADIO_POLICY_HPP
#define SIMPLEBCM_RADIO_POLICY_HPP

#include "Payload.hpp"
#include <IOKit/IOService.h>

namespace bcm {

constexpr const char *RadioPolicyVersion = "1.2.1";

class RadioPolicy {
public:
    static bool prepare(LinkedImage &image);
    static void publish(IOService *service);
};

}

#endif
