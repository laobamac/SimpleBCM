//
//  Loader.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_LOADER_HPP
#define SIMPLEBCM_LOADER_HPP

#include <IOKit/IOService.h>

namespace bcm {
bool preparePayloads();
bool startPayloads();
void publishLoader(IOService *service);
}

#endif
