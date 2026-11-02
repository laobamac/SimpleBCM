//
//  NativeUserClient.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_NATIVE_USER_CLIENT_HPP
#define SIMPLEBCM_NATIVE_USER_CLIENT_HPP

#include <IOKit/IOUserClient.h>

namespace bcm {

bool prepareNativeUserClients();
IOReturn wrapNativeUserClient(IOReturn, task_t, void *, uint32_t,
                              OSDictionary *, IOUserClient **);

}

#endif
