package es.caib.seycon.idp.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Iterator;
import java.util.Map;

public class ReplaceFilter {
    Map<String,String> filters;

    public ReplaceFilter (Map<String,String> filters) {
        this.filters = filters;
    }
    
    public void process (InputStream in, OutputStream out) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(in));
        BufferedWriter w = new BufferedWriter(new OutputStreamWriter(out));
        do {
            String line = r.readLine();
            
            if (line == null) break;
            
            for (Iterator<String> it = filters.keySet().iterator(); it.hasNext(); ) {
                String key = it.next();
                String value = filters.get(key);
                if (value == null)
                    value = "[Unknown]"; //$NON-NLS-1$
                line = line.replace(key, value);
            }
            w.write(line);
            w.newLine();
        } while (true);
        r.close();
        w.close();
    }
}
