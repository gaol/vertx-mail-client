/*
 *  Copyright (c) 2011-2021 The original author or authors
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

package io.vertx.ext.mail;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.CompositeFuture;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.VertxOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.subethamail.wiser.WiserMessage;

import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.core.Is.is;

/**
 * This tests a situation when massive mount of emails got sent in different contexts.
 *
 * @author <a href="mailto:aoingl@gmail.com">Lin Gao</a>
 */
@RunWith(VertxUnitRunner.class)
public class MassiveMailSendingTest extends SMTPTestWiser {

  private static final Map<String, JsonObject> EMAILS = new HashMap<>();

  private class SendMailVerticle extends AbstractVerticle {
    private MailClient mailClient;

    @Override
    public void start() {
      mailClient = MailClient.create(vertx, configLogin());
      vertx.eventBus().<JsonObject>consumer("send.email", m -> {
        final MailMessage mailMessage = new MailMessage(m.body());
        mailClient.sendMail(mailMessage, sr -> {
          assertTrue(sr.succeeded());
          assertTrue(sr.result().getRecipients().containsAll(mailMessage.getTo()));
          m.reply(new JsonObject()
            .put("subject", m.body().getString("subject"))
            .put("content", m.body().getString("content"))
          );
        });
      });
    }

    @Override
    public void stop() throws Exception {
      mailClient.close();
    }
  }

  @Test
  public void sentMassiveEmails(TestContext testContext) {
    final int count = 1000;
    Async async = testContext.async(count);
    // deploy the verticle multiple instances
    vertx.deployVerticle(SendMailVerticle::new, new DeploymentOptions().setInstances(VertxOptions.DEFAULT_EVENT_LOOP_POOL_SIZE))
      .flatMap(ps -> {
        testContext.put("did", ps);
        List<Future> futures = new ArrayList<>();
        for (int i = 0; i < count; i ++) {
          final String key = String.valueOf(i);
          final JsonObject json = new MailMessage()
            .setFrom("from" + i + "@example.com")
            .setTo("to" + i + "@example.com")
            .setSubject("may the world peace " + i)
            .setText("Hope the COVID-19 vanishes soon " + i + "\n")
            .addHeader("key", key)
            .toJson();
          EMAILS.put(key, json);
          futures.add(vertx.eventBus().<JsonObject>request("send.email", json).onSuccess(m -> {
              assertThat(m.body().getString("subject"), is(json.getString("subject")));
            assertThat(m.body().getString("content"), is(json.getString("content")));
              async.countDown();
          }));
        }
        return CompositeFuture.all(futures);
      })
    .onComplete(v -> {
      // find received emails and verify that content matches subject
      for (WiserMessage wm: wiser.getMessages()) {
        try {
          MimeMessage mm = wm.getMimeMessage();
          String key = mm.getHeader("key")[0];
          assertNotNull(key);
          JsonObject expected = EMAILS.get(key);
          assertEquals(expected.getString("from"), mm.getFrom()[0].toString());
          assertEquals(expected.getString("to"), "[" + mm.getRecipients(Message.RecipientType.TO)[0].toString() + "]");
          assertEquals(expected.getString("subject"), mm.getSubject());
          assertEquals(expected.getString("text"), TestUtils.conv2nl(TestUtils.inputStreamToString(mm.getInputStream())));
        } catch (Exception e) {
          fail(e);
        }
      }
    })
    .onComplete(testContext.asyncAssertSuccess(va -> vertx.undeploy(testContext.get("did"), testContext.asyncAssertSuccess(v -> EMAILS.clear()))));
  }

}
