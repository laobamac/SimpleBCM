//
//  AWDLCoexistence.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/8.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_AWDL_COEXISTENCE_HPP
#define SIMPLEBCM_AWDL_COEXISTENCE_HPP

#include "Payload.hpp"
#include <IOKit/IOService.h>

namespace bcm {

class AWDLCoexistence {
public:
    static bool prepare(LinkedImage &image, bool enabled);
    static void publish(IOService *service);
};

}

#endif
