//
//  NativeSkywalk.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_NATIVE_SKYWALK_HPP
#define SIMPLEBCM_NATIVE_SKYWALK_HPP

#include "Payload.hpp"
#include "NativeProfile.hpp"
#include <IOKit/IOService.h>

namespace bcm {

bool validateNativeSkywalk();
bool prepareNativeSkywalk(LinkedImage *, size_t);
void publishNativeSkywalk(IOService *);
IOReturn nativeSkywalkUserClient(IOService *, task_t, void *, uint32_t,
                                OSDictionary *, IOUserClient **);
IOReturn createSkywalkUserClient(IOService *, task_t, void *, uint32_t,
                                OSDictionary *, IOUserClient **);

}

#endif
