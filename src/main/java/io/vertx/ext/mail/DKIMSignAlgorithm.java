/*
 *  Copyright (c) 2011-2019 The original author or authors
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

/**
 *
 * Signing Algorithm specified by DKIM spec.
 *
 * @author <a href="mailto: aoingl@gmail.com">Lin Gao</a>
 */
public enum DKIMSignAlgorithm {
  RSA_SHA1("RS1", "rsa", "sha1"), // rsa-sha1
  RSA_SHA256("RS256", "rsa", "sha256"); // rsa-sha256

  // alias is the same as defined in vertx-auth-common to be able to get defined HashingAlgorithm
  private String alias;
  private String type;
  private String hashAlgo;

  DKIMSignAlgorithm(String alias, String type, String hashAlgo) {
    this.alias = alias;
    this.type = type;
    this.hashAlgo = hashAlgo;
  }

  /**
   * Gets the algorithm alias.
   *
   * @return the algorithm alisa
   */
  public String getAlias() {
    return alias;
  }

  /**
   * Gets the algorithm name.
   *
   * See: https://tools.ietf.org/html/rfc6376#section-3.3
   *
   * @return the algorithm name
   */
  public String getAlgorightmName() {
    return this.type + "-" + hashAlgo;
  }

  /**
   * Gets the hash algorithm to produce the hash of the message.
   *
   * @return the hash algorithm
   */
  public String getHashAlgorithm() {
    return this.hashAlgo;
  }

  /**
   * Gets the Signature Algorithm, like: SHA256withRSA, SHA1withRSA.
   *
   * @return the signature algorithm
   */
  public String getSignatureAlgorithm() {
    return this.hashAlgo.toUpperCase() + "with" + this.type.toUpperCase();
  }

}
