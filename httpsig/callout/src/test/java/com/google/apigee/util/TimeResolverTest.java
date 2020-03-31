package com.google.apigee.util;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;

//import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TimeResolverTest {

  @Test
  public void testResolution() {
    Assert.assertEquals(TimeResolver.resolveExpression("30s"), Long.valueOf(30));
    Assert.assertEquals(TimeResolver.resolveExpression("180s"), Long.valueOf(180));
    Assert.assertEquals(TimeResolver.resolveExpression("1m"), Long.valueOf(60));
    Assert.assertEquals(TimeResolver.resolveExpression("10m"), Long.valueOf(600));
    Assert.assertEquals(TimeResolver.resolveExpression("2h"), Long.valueOf(7200));
  }

}
