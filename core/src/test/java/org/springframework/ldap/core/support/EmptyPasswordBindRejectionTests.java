/*
 * Copyright 2005-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.ldap.core.support;

import java.util.Hashtable;

import javax.naming.ldap.LdapContext;

import org.junit.Test;

import org.springframework.ldap.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * Regression tests for CVE-2026-41720: the built-in
 * {@link DirContextAuthenticationStrategy} implementations must reject a bind
 * that pairs a non-empty principal with an empty/null password. That pairing is
 * the RFC 4513 5.1.2 unauthenticated-bind shape, which many directories accept
 * as anonymous and report as success — an authentication bypass.
 *
 * <p>Backpatch-fresh: not present upstream in 2.4.x. Mirrors the guard added in
 * spring-projects/spring-ldap@e2748d44bdce4f6cb4663b9b8d8462e34808f09c.
 *
 * @see SimpleDirContextAuthenticationStrategy
 * @see DigestMd5DirContextAuthenticationStrategy
 * @see DefaultTlsDirContextAuthenticationStrategy
 */
public class EmptyPasswordBindRejectionTests {

	private static final String USER_DN = "cn=admin,dc=example,dc=com";

	@Test
	public void simpleStrategyRejectsEmptyPassword() {
		SimpleDirContextAuthenticationStrategy strategy = new SimpleDirContextAuthenticationStrategy();
		Hashtable<String, Object> env = new Hashtable<>();

		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(() -> strategy.setupEnvironment(env, USER_DN, ""));
		// Guard must fire before the environment is populated.
		assertThat(env).isEmpty();
	}

	@Test
	public void digestMd5StrategyRejectsEmptyPassword() {
		DigestMd5DirContextAuthenticationStrategy strategy = new DigestMd5DirContextAuthenticationStrategy();
		Hashtable<String, Object> env = new Hashtable<>();

		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(() -> strategy.setupEnvironment(env, USER_DN, ""));
		assertThat(env).isEmpty();
	}

	@Test
	public void defaultTlsStrategyRejectsEmptyPassword() {
		DefaultTlsDirContextAuthenticationStrategy strategy = new DefaultTlsDirContextAuthenticationStrategy();
		LdapContext ctx = mock(LdapContext.class);

		// Guard must fire before any interaction with the context (no bind,
		// no forced lookup); the mock stays untouched.
		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(() -> strategy.applyAuthentication(ctx, USER_DN, ""));
	}

}
