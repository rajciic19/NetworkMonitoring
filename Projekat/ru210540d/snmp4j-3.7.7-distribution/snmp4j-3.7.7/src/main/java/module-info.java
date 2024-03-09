/*_############################################################################
  _## 
  _##  SNMP4J - module-info.java  
  _## 
  _##  Copyright (C) 2003-2022  Frank Fock (SNMP4J.org)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/

module org.snmp4j {
    requires transitive java.logging;
    exports org.snmp4j;
    exports org.snmp4j.asn1;
    exports org.snmp4j.event;
    exports org.snmp4j.log;
    exports org.snmp4j.mp;
    exports org.snmp4j.security;
    exports org.snmp4j.security.dh;
    exports org.snmp4j.security.nonstandard;
    exports org.snmp4j.smi;
    exports org.snmp4j.transport.tls;
    exports org.snmp4j.transport;
    exports org.snmp4j.uri;
    exports org.snmp4j.util;
    exports org.snmp4j.version;
    exports org.snmp4j.fluent;
    exports org.snmp4j.cfg;
}
