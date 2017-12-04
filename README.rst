Slack Authenticator Plugin
=============================

Slack Oauth Authenticator plugin for the Curity Identity Server.

Create `Slack app`_

Create Slack Authenticator and configure following values.

Config
~~~~~~

+-------------------+--------------------------------------------------+-----------------------------+
| Name              | Default                                          | Description                 |
+===================+==================================================+=============================+
| ``Client ID``     |                                                  | Slack app client id         |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Client Secret`` |                                                  | Slack app secret key        |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Authorization`` | https://slack.com/oauth/authorize                | URL to the Slack            |
| ``Endpoint``      |                                                  | authorization endpoint      |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Token``         | https://slack.com/api/oauth.access               | URL to the Slack            |
| ``Endpoint``      |                                                  | authorization endpoint      |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Scope``         |                                                  | A space-separated list of   |
|                   |                                                  | scopes to request from      |
|                   |                                                  | Slack                       |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Team``          |                                                  | Slack team ID of a          |
|                   |                                                  | workspace to attempt to     |
|                   |                                                  | restrict to                 |
+-------------------+--------------------------------------------------+-----------------------------+
| ``User Info``     | https://slack.com/api/users.info                 | URL to the Slack            |
| ``Endpoint``      |                                                  | userinfo(profile) endpoint  |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+

Build plugin
~~~~~~~~~~~~

First, collect credentials to the Curity Nexus, to be able to fetch the
SDK. Add nexus credentials in maven settings.

Then, build the plugin by: ``mvn clean package``

Install plugin
~~~~~~~~~~~~~~

| To install a plugin into the server, simply drop its jars and all of
  its required resources, including Server-Provided Dependencies, in the
  ``<plugin_group>`` directory.
| Please visit `curity.io/plugins`_ for more information about plugin
  installation.

Required dependencies/jars
"""""""""""""""""""""""""""""""""""""

Following jars must be in plugin group classpath.

-  `commons-codec-1.9.jar`_
-  `commons-logging-1.2.jar`_
-  `google-collections-1.0-rc2.jar`_
-  `httpclient-4.5.jar`_
-  `httpcore-4.4.1.jar`_
-  `identityserver.plugins.authenticators-1.0.0.jar`_

Please visit `curity.io`_ for more information about the Curity Identity
Server.

.. _Slack app: https://api.slack.com/apps
.. _curity.io/plugins: https://support.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation
.. _commons-codec-1.9.jar: http://central.maven.org/maven2/commons-codec/commons-codec/1.9/commons-codec-1.9.jar
.. _commons-logging-1.2.jar: http://central.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar
.. _google-collections-1.0-rc2.jar: http://central.maven.org/maven2/com/google/collections/google-collections/1.0-rc2/google-collections-1.0-rc2.jar
.. _httpclient-4.5.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5/httpclient-4.5.jar
.. _httpcore-4.4.1.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.1/httpcore-4.4.1.jar
.. _identityserver.plugins.authenticators-1.0.0.jar: https://github.com/curityio/authenticator-plugin
.. _curity.io: https://curity.io/
