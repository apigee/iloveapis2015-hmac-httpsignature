// CalloutBase.java
// ------------------------------------------------------------------
//
// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callout.httpsignature;

import com.apigee.flow.message.MessageContext;
import com.google.common.base.Splitter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class CalloutBase {
  public static final String REQUEST_TARGET = "(request-target)";
  private static final String _varprefix = "httpsig_";
  private static final String commonError = "^(.+?)[:;] (.+)$";
  private static final Pattern commonErrorPattern = Pattern.compile(commonError);
  protected static final Function<Iterable, String> commaJoiner = getJoiner(",");
  protected static final Function<Iterable, String> spaceJoiner = getJoiner(" ");

  private static final Splitter spaceSplitter = Splitter.on(' ').trimResults();
  protected Map<String, String> properties; // read-only

  public CalloutBase(Map properties) {
    // convert the untyped Map to a generic map
    Map<String, String> m = new HashMap<String, String>();
    Iterator iterator = properties.keySet().iterator();
    while (iterator.hasNext()) {
      Object key = iterator.next();
      Object value = properties.get(key);
      if ((key instanceof String) && (value instanceof String)) {
        m.put((String) key, (String) value);
      }
    }
    this.properties = Collections.unmodifiableMap(m);
  }

  static String varName(String s) {
    return _varprefix + s;
  }

  protected static Function<Iterable, String> getJoiner(String separator) {
    return (list) -> {
      String result = "";
      int ix = 0;
      for (Object s : list) {
        if (ix++ > 0) {
          result += separator;
        }
        result += (String) s;
      }
      return result;
    };
  }

  protected static String getMultivaluedHeader(MessageContext msgCtxt, String header) {
    String name = header + ".values";
    return commaJoiner.apply((ArrayList) msgCtxt.getVariable(name));
  }

  protected HttpSignature getFullSignature(MessageContext msgCtxt) throws IllegalStateException {
    // consult the property first. If it is not present, retrieve the
    // request header.
    String signature = ((String) this.properties.get("fullsignature"));
    if (signature != null) {
      signature = signature.trim();
      signature = PackageUtils.resolvePropertyValue(signature, msgCtxt);
      if (signature == null || signature.equals("")) {
        throw new IllegalStateException("fullsignature does not resolve.");
      }
    } else {
      // In draft 01, the header was "Authorization".
      // As of draft 03, the header is "Signature".
      // In later drafts, it's "Authorization" with a Signature type.

      // NB: In Edge, getting a header that includes a comma requires getting
      // the .values, which is an ArrayList of strings.
      //
      signature = getMultivaluedHeader(msgCtxt, "request.header.Authorization");
      if (signature == null) {
        throw new IllegalStateException("signature is not specified.");
      }
      signature = signature.trim();
    }
    if (signature.equals("")) {
      throw new IllegalStateException("fullsignature is empty.");
    }

    HttpSignature httpsig = HttpSignature.forVerification(signature);
    return httpsig;
  }

  protected List<String> getHeaders(MessageContext msgCtxt) {
    String headers = (String) this.properties.get("headers");
    if (headers == null) {
      return null;
    }
    headers = headers.trim();
    if (headers.equals("")) {
      return null;
    }
    headers = PackageUtils.resolvePropertyValue(headers, msgCtxt);
    if (headers == null || headers.equals("")) {
      // Uncomment the below to force configuration to require a
      // headers property
      // throw new IllegalStateException("headers resolves to an empty string");
      return null;
    }
    return spaceSplitter.splitToList(headers);
  }

  protected boolean getDebug() {
    String value = (String) this.properties.get("debug");
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }

  protected class EdgeHeaderProvider implements ReadOnlyHttpSigHeaderMap {
    MessageContext c;

    public EdgeHeaderProvider(MessageContext msgCtxt) {
      c = msgCtxt;
    }

    public String getHeaderValue(String key) {
      String value = null;

      if (key.equals(REQUEST_TARGET)) {
        try {
          // in HTTP Signature, the "path" includes the url path + query
          URI uri = new URI(c.getVariable("proxy.url").toString());

          String path = uri.getPath();
          if (uri.getQuery() != null) {
            path += "?" + uri.getQuery();
          }

          value = c.getVariable("request.verb");
          if (value == null || value.equals("")) value = "unknown verb";
          value = value.toLowerCase() + " " + path;

        } catch (URISyntaxException exc1) {
          value = "none";
        }
      } else {
        value = c.getVariable("request.header." + key);
      }
      return value;
    }
  }

}
