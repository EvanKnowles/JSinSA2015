package za.co.knonchalant.jsinsa.xss;

/**
 * Created by evan on 15/06/25.
 */
public class MarkupSanitizer implements ISanitarium {
    @Override
    public String sanitize(String input) {
        return input.replaceAll("<", "&lt;").replace(">", "&gt;");
    }
}
