/*
 *  *******************************************************************************
 *  Copyright (c) 2023-24 Harman International
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  *******************************************************************************
 */

package org.eclipse.ecsp.config;

import jakarta.annotation.Resource;
import org.eclipse.ecsp.auth.lib.config.AuthProperty;
import org.eclipse.ecsp.common.config.EnvConfig;
import org.eclipse.ecsp.common.config.EnvConfigLoader;
import org.eclipse.ecsp.springauth.client.rest.SpringAuthRestClient;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for HcpAuthLib.
 * This class provides configuration for the HcpAuthLib library.
 */
@Configuration
@ComponentScan(basePackages = "org.eclipse.ecsp")
@ImportAutoConfiguration(RestTemplateAutoConfiguration.class)
public class HcpAuthLibConfig {

    @Resource(name = "hcpAuthLibConfigLoader")
    private EnvConfigLoader<AuthProperty> envConfigLoader;

    /**
     * Creates an instance of the EnvConfigLoader for the HcpAuthLibConfig class.
     *
     * @return The EnvConfigLoader instance.
     */
    @Bean(name = "hcpAuthLibConfigLoader")
    public EnvConfigLoader<AuthProperty> envConfigLoader() {
        return new EnvConfigLoader<>(AuthProperty.class, "auth");
    }

    /**
     * Creates an instance of the EnvConfig for the HcpAuthLibConfig class.
     *
     * @return The EnvConfig instance.
     */
    @Bean(name = "envConfig")
    public EnvConfig<AuthProperty> envConfig() {
        return envConfigLoader.getServerConfig();
    }

    /**
     * Creates an instance of the SpringAuthRestClient for the HcpAuthLibConfig class.
     *
     * @param envConfig The EnvConfig instance.
     * @return The SpringAuthRestClient instance.
     */
    @Bean
    public SpringAuthRestClient springAuthRestClient(EnvConfig<AuthProperty> envConfig) {
        return new SpringAuthRestClient(envConfig.getStringValue(AuthProperty.SPRING_AUTH_BASE_URL));
    }
}
