/*
 *  Copyright (c) 2011-2015 The original author or authors
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *       The Eclipse Public License is available at
 *       http://www.eclipse.org/legal/epl-v10.html
 *
 *       The Apache License v2.0 is available at
 *       http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

/**
 *
 */
package io.vertx.ext.mail.impl;

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.ext.mail.MailConfig;
import io.vertx.ext.mail.SMTPTestWiser;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * a few tests using the dummy server
 * @author <a href="http://oss.lehmann.cx/">Alexander Lehmann</a>
 */
@RunWith(VertxUnitRunner.class)
public class SMTPConnectionPoolDummySMTPTest extends SMTPTestWiser {

  /**
   *
   */
  private static final String HOSTNAME = "my.hostname.com";

  private static final Logger log = LoggerFactory.getLogger(SMTPConnectionPoolDummySMTPTest.class);

  private final MailConfig config = configNoSSL();

  @Test
  public final void testGetConnectionAfterReturn(TestContext testContext) {

    SMTPConnectionPool pool = new SMTPConnectionPool(vertx, config.setMaxPoolSize(1));
    Async async = testContext.async();

    testContext.assertEquals(0, pool.connCount());

    pool.getConnection(HOSTNAME, vertx.getOrCreateContext(), result -> {
      if (result.succeeded()) {
        log.debug("got 1st connection");
        testContext.assertEquals(1, pool.connCount());
        result.result().returnToPool().onComplete(testContext.asyncAssertSuccess(v -> {
          testContext.assertEquals(1, pool.connCount());

          pool.getConnection(HOSTNAME, vertx.getOrCreateContext(), result2 -> {
            if (result2.succeeded()) {
              log.debug("got 2nd connection");
              testContext.assertEquals(1, pool.connCount());
              result2.result().returnToPool().onComplete(testContext.asyncAssertSuccess(vv -> pool.close(vvv -> {
                testContext.assertEquals(0, pool.connCount());
                async.complete();
              })));
            } else {
              log.info(result2.cause());
              testContext.fail(result2.cause());
            }
          });
        }));
      } else {
        log.info(result.cause());
        testContext.fail(result.cause());
      }
    });
  }

}
