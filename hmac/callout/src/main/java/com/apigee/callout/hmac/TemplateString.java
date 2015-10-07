package com.apigee.callout.hmac;

import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;


public class TemplateString {
    private final Pattern tmpltPattern =
        Pattern.compile("\\{([^\\}]+)\\}", Pattern.CASE_INSENSITIVE);
    public ArrayList<String> variableNames;
    public String template;
    private void injectDollar(int position) {
        template =
            template.substring(0, position) +
            "$" + template.substring(position, template.length());
    }
    public TemplateString(String s) {
        this.variableNames = new ArrayList<String>();
        examineString(s);
    }

    private void examineString(String input) {
        this.template = input;
        int x = 0;
        Matcher m = tmpltPattern.matcher(input);
        while (m.find()) {
            variableNames.add(m.group(1));
            injectDollar(m.start() + x++);
        }
    }
}
