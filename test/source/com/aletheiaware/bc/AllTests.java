/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aletheiaware.bc;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        com.aletheiaware.bc.FileCacheTest.class,
        com.aletheiaware.bc.MemoryCacheTest.class,
        com.aletheiaware.bc.NodeTest.class,
        com.aletheiaware.bc.PoWChannelTest.class,
        com.aletheiaware.bc.TCPNetworkTest.class,
        com.aletheiaware.bc.utils.BCUtilsTest.class,
        com.aletheiaware.bc.utils.ChannelUtilsTest.class
})
public class AllTests {
    //nothing
}