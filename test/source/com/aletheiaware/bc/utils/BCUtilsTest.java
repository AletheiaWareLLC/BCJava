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

package com.aletheiaware.bc.utils;

import com.aletheiaware.crypto.Crypto;

import java.security.KeyPair;

import org.junit.Assert;
import org.junit.Test;

public class BCUtilsTest {

    private static KeyPair keys = null;

    public static String getTestAlias() {
        return "Alice";
    }

    public static KeyPair getTestKeys() throws Exception {
        if (keys == null) {
            keys = Crypto.createRSAKeyPair();
        }
        return keys;
    }

    @Test
    public void empty() {
        // TODO
    }
}