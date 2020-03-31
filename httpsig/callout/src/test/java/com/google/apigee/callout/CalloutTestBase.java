package com.google.apigee.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import org.testng.annotations.BeforeMethod;

public abstract class CalloutTestBase {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  protected MessageContext msgCtxt;
  protected ExecutionContext exeCtxt;

  @BeforeMethod()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map variables;

          public void $init() {
            variables = new HashMap();
          }

          @Mock()
          public <T> T getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            T value = (T) variables.get(name);
            System.out.printf("getVariable(%s) => %s\n", name, (value==null)?"null": value.toString());
            return value;
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap();
            }
            System.out.printf("setVariable(%s) <= %s\n", name, (value==null)?"null": value.toString());

            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            if (variables.containsKey(name)) {
              System.out.printf("removeVariable(%s)\n", name);
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
  }
}
