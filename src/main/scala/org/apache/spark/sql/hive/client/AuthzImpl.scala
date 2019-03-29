/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.sql.hive.client

import java.util.concurrent.ConcurrentHashMap
import java.util.{List => JList}

import com.githup.yaooqinn.spark.authorizer.Logging
import org.apache.hadoop.hive.ql.security.authorization.plugin._
import org.apache.hadoop.hive.ql.session.SessionState
import org.apache.hadoop.security.UserGroupInformation
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.hive.{AuthzUtils, HiveExternalCatalog}
import org.apache.spark.sql.internal.NonClosableMutableURLClassLoader
import scala.collection.JavaConverters._

/**
  * A Tool for Authorizer implementation.
  *
  * The [[SessionState]] generates the authorizer and authenticator, we use these to check
  * the privileges of a Spark LogicalPlan, which is mapped to hive privilege objects and operation
  * type.
  *
  * [[SparkSession]] with hive catalog implemented has its own instance of [[SessionState]]. I am
  * strongly willing to reuse it, but for the reason that it belongs to an isolated classloader
  * which makes it unreachable for us to visit it in Spark's context classloader. So, when
  * [[ClassCastException]] occurs, we turn off [[IsolatedClientLoader]] to use Spark's builtin
  * Hive client jars to generate a new metastore client to replace the original one, once it is
  * generated, will be reused then.
  *
  */
object AuthzImpl extends Logging {

  private val userToSession: ConcurrentHashMap[String, SessionState] = new ConcurrentHashMap[String, SessionState]()

  def checkPrivileges(sparkSession: SparkSession,
                      hiveOpType: HiveOperationType,
                      inputObjs: JList[HivePrivilegeObject],
                      outputObjs: JList[HivePrivilegeObject],
                      context: HiveAuthzContext): Unit = {
    val metaHive = sparkSession.sharedState
      .externalCatalog.unwrapped.asInstanceOf[HiveExternalCatalog]
      .client
    var sessionState: SessionState = null
    info(s"Get MetaDataHive${metaHive}")
    info(s"Get metaHive.state ${metaHive.getState}")
    val user = UserGroupInformation.getCurrentUser.getShortUserName
    info(s"Current User ${user}")
    info(s"is empyrt? ${userToSession.isEmpty}")
    if (!userToSession.isEmpty)
      userToSession.asScala.foreach(kv => {
        info(s"user => ${kv._1} , sessionstate => ${kv._2}")
      })
    if (userToSession.containsKey(user)) {
      sessionState = userToSession.get(user)
    }
    else {
      metaHive.withHiveState {
        info(s"Thread => ${Thread.currentThread().getId}")
        sessionState = SessionState.get()
      }
      userToSession.put(user, sessionState)
    }

    info(s"Get SessionState....${sessionState}")
    if (sessionState.getUserName == null) {
      info(s"Set User ${UserGroupInformation.getCurrentUser.getShortUserName}")
      AuthzUtils.setFieldVal(sessionState, "userName", UserGroupInformation.getCurrentUser.getShortUserName)
    }

    info(s"Get SessionState User...${sessionState.getUserName}")
    val authorizer = sessionState.getAuthorizerV2
    metaHive.withHiveState {
      if (authorizer != null) {
        try {
          authorizer.checkPrivileges(hiveOpType, inputObjs, outputObjs, context)
        } catch {
          case hae: HiveAccessControlException =>
            error(
              s"""
                 |+===============================+
                 ||Spark SQL Authorization Failure|
                 ||-------------------------------|
                 ||${hae.getMessage}
                 ||-------------------------------|
                 ||Spark SQL Authorization Failure|
                 |+===============================+
               """.stripMargin)
            throw hae
          case e: Exception => throw e
        }
      } else {
        warn("Authorizer V2 not configured. Skipping privilege checking")
      }
    }
  }
}

