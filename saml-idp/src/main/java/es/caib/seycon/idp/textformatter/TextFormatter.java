package es.caib.seycon.idp.textformatter;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

public class TextFormatter {
    int exclusions = 0;

    protected static final String LOOP_OPEN_TAG = "{if "; //$NON-NLS-1$
    protected static final String LOOP_END_TAG = "{endif}"; //$NON-NLS-1$

    protected static final String DATA_START_TOKEN = "${"; //$NON-NLS-1$
    protected static final String END_TOKEN = "}"; //$NON-NLS-1$

    public String formatString(String rawText, ResourceBundle rb, Map params)
            throws TextFormatException {

        int conditionBegin = rawText.indexOf(LOOP_OPEN_TAG);
        int endConditionBegin = rawText.indexOf(LOOP_END_TAG);
        if (conditionBegin >= 0) {
            if (exclusions > 0)
                exclusions++;
            else {
                int conditionEnd = rawText.indexOf(END_TOKEN);
                String conditionName = rawText.substring(conditionBegin
                        + LOOP_OPEN_TAG.length(), conditionEnd);
                String value = (String) params.get(conditionName);
                if (value == null || "false".equals(value)) {
                    exclusions++;
                }
            }
            return ""; //$NON-NLS-1$
        } else if (endConditionBegin >= 0) {
            if (exclusions > 0)
                exclusions--;
            return ""; //$NON-NLS-1$
        } else if (exclusions > 0) {
            return ""; //$NON-NLS-1$
        } else {
            int openTagLength = DATA_START_TOKEN.length();
            int endTokenSize = END_TOKEN.length();

            int initialSearchIdx = 0;
            int idxLoop;
            StringBuffer b = new StringBuffer();
            while ((idxLoop = rawText.indexOf(DATA_START_TOKEN,
                    initialSearchIdx)) >= initialSearchIdx) {
                int endTokenIdx = rawText.indexOf(END_TOKEN, idxLoop);
                if (endTokenIdx < idxLoop) {
                    throw new TextFormatException(
                            "ERROR : THERE IS A DATA TAG NOT CLOSED: " //$NON-NLS-1$
                                    + rawText);

                }
                b.append(rawText.subSequence(initialSearchIdx, idxLoop));
                String tag = rawText.substring(idxLoop + openTagLength,
                        endTokenIdx);
                boolean raw = false;
                if (tag.startsWith("raw:"))
                {
                	raw = true;
                	tag = tag.substring(4);
                }
                String value = (String) params.get(tag);
                if (value == null) {
                    try {
                        value = rb.getString(tag);
                    } catch (MissingResourceException e) {
                        value = "[[" + tag + "]]"; //$NON-NLS-1$ //$NON-NLS-2$
                    }
                }
                else 
                {
                	if (!raw)
                		value = value.replace("&", "&amp;").replace("'", "&apos;") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                            .replace("\"", "&quot;").replace("<", "&lt;") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                            .replace(">", "&gt;"); //$NON-NLS-1$ //$NON-NLS-2$
                }
                b.append(value);

                initialSearchIdx = endTokenIdx + endTokenSize;

            }
            b.append(rawText.subSequence(initialSearchIdx, rawText.length()));
            return b.toString();
        }
    }

    public void formatTemplate(InputStream is, OutputStream out,
            ResourceBundle rb, Map params) throws TextFormatException {
        try {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(is, "UTF-8")); //$NON-NLS-1$
            String line;
            while ((line = reader.readLine()) != null) {
                String s = formatString(line, rb, params);
                out.write(s.getBytes("UTF-8")); //$NON-NLS-1$
                out.write('\r');
                out.write('\n');
            }
            if (reader != null)
                reader.close();
        } catch (FileNotFoundException e) {
            throw new TextFormatException(e);
        } catch (IOException ioe) {
            throw new TextFormatException(ioe);
        }
    }

}
