package za.co.knonchalant.jsinsa.xss;

/**
 * Created by evan on 15/06/25.
 */
public class BasicCaseInsensitiveSanitizer implements ISanitarium {
    @Override
    public String sanitize(String input) {
        return input.replaceAll("(?i)script", "");
    }
}
