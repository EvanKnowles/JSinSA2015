package za.co.knonchalant.jsinsa.xss;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by evan on 15/06/23.
 */
@WebServlet("/xss")
public class XssServlet extends HttpServlet {
    private static final String OPTION = "<option value='%s'>%s</option>";
    private static final String OPTION_SELECTED = "<option value='%s' selected>%s</option>";
    private static Map<String, ISanitarium> sanitizers = new HashMap<String, ISanitarium>();
    private static List<String> history = new ArrayList<String>();

    static {
        sanitizers.put("none", new NoSanitizer());
        sanitizers.put("basic", new BasicSanitizer());
        sanitizers.put("basic-case", new BasicCaseInsensitiveSanitizer());
        sanitizers.put("markup", new MarkupSanitizer());
    }

    @Override
    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        Map<String, String[]> parameterMap = httpServletRequest.getParameterMap();

        String input = getString(parameterMap, "trusted-input");
        String method = getString(parameterMap, "method");
        String headerString = getString(parameterMap, "header");
        boolean header = !"".equals(headerString);

        printResponse(httpServletResponse, header, input, method);
    }

    private String getString(Map<String, String[]> parameterMap, String key) {
        String input = "";
        if (parameterMap != null) {
            String[] x = parameterMap.get(key);
            if (x != null) {
                for (String xs : x) {
                    input += xs;
                }
            }
        }
        return input;
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        String pathInfo = httpServletRequest.getPathInfo();
        if (pathInfo.contains("css")) {
            writeCSS(httpServletResponse);
            return;
        }

        if (pathInfo.contains("images")) {
            writeJiff(pathInfo, httpServletResponse);
            return;
        }

        Map<String, String[]> parameterMap = httpServletRequest.getParameterMap();

        String method = getString(parameterMap, "method");
        String headerString = getString(parameterMap, "header");
        String isAdmin = getString(parameterMap, "isAdmin");
        String wipe = getString(parameterMap, "wipe");
        if (!"".equals(isAdmin)) {
            httpServletRequest.getSession().setAttribute("admin", true);
        }

        Object adminObject = httpServletRequest.getSession().getAttribute("admin");
        if (adminObject != null && (Boolean) adminObject && !"".equals(wipe)) {
            history = new ArrayList<String>();
        }

        boolean header = !"".equals(headerString);
        printResponse(httpServletResponse, header, "", method);
    }

    private void writeJiff(String pathInfo, HttpServletResponse response) throws IOException {
        String fileName = "/WEB-INF/" + pathInfo;
        InputStream resourceAsStream = getServletContext().getResourceAsStream(fileName);
        String extension = fileName.substring(fileName.indexOf(".") + 1);
        response.setContentType("image/" + extension);

        OutputStream out = response.getOutputStream();
        copy(resourceAsStream, out);
        out.close();
    }

    public void copy(final InputStream in, final OutputStream out) throws IOException {
        byte[] buffer = new byte[1024];
        int count;

        while ((count = in.read(buffer)) != -1) {
            out.write(buffer, 0, count);
        }

        // Flush out stream, to write any remaining buffered data
        out.flush();
    }

    private void writeCSS(HttpServletResponse httpServletResponse) throws IOException {
        InputStream resourceAsStream = getServletContext().getResourceAsStream("/WEB-INF/xss.css");

        String page = copyToString(resourceAsStream);

        PrintWriter writer = httpServletResponse.getWriter();
        writer.append(page);
        writer.flush();
        writer.close();
    }

    private void printResponse(HttpServletResponse httpServletResponse, boolean header, String input, String method) throws IOException {
        if (!header) {
            httpServletResponse.addHeader("X-XSS-Protection", "0");
        }

        InputStream resourceAsStream = getServletContext().getResourceAsStream("/WEB-INF/xss.html");

        String sanitized = sanitize(input, method);
        if (!"".equals(sanitized)) {
            sanitized = wrap(sanitized);
            history.add(sanitized);
        }
        String page = copyToString(resourceAsStream);
        page = page.replace("{{YOUR AD HERE}}", toString(history));
        page = page.replace("{{METHOD}}", method);
        page = page.replace("{{SANITIZE_OPTIONS}}", getOptions(method));
        page = page.replace("{{header}}", header ? "checked" : "");

        PrintWriter writer = httpServletResponse.getWriter();
        writer.append(page);
        writer.flush();
        writer.close();
    }

    private String wrap(String sanitized) {
        InputStream resourceAsStream = getServletContext().getResourceAsStream("/WEB-INF/comment.html");
        String comment = copyToString(resourceAsStream);
        comment = comment.replace("{{COMMENT}}", sanitized);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("'at ' hh:mm zz");
        comment = comment.replace("{{TIME}}", simpleDateFormat.format(new Date()));
        return comment;
    }

    private String toString(List<String> history) {
        StringBuilder all = new StringBuilder();
        for (int i = history.size() - 1; i >= 0; i--) {
            all.append(history.get(i));
        }
        return all.toString();
    }

    private String sanitize(String input, String method) {
        ISanitarium sanitarium = sanitizers.get(method);

        if (sanitarium == null) {
            return input;
        }

        return sanitarium.sanitize(input);
    }

    private String copyToString(InputStream in) {
        return new Scanner(in, "UTF-8").useDelimiter("\\A").next();
    }

    public String getOptions(String method) {
        StringBuilder result = new StringBuilder(String.format(OPTION, "", ""));
        for (String sanitizer : sanitizers.keySet()) {
            if (!method.equals(sanitizer)) {
                result.append(String.format(OPTION, sanitizer, sanitizer));
            } else {
                result.append(String.format(OPTION_SELECTED, sanitizer, sanitizer));
            }
        }
        return result.toString();
    }
}
