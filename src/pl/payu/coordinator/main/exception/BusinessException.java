package pl.payu.coordinator.main.exception;

public class BusinessException extends Exception {
    private static final long serialVersionUID = 4563658991515907387L;

    // TODO sprawdzić czy używane i ew.
    public static final String PACKAGE_NOTIFY = "checkout.errors.package.notify";
    public static final String PACKAGE_PROCESS = "checkout.errors.package.process";
    public static final String PACKAGE_SIGNATURE = "checkout.errors.package.signature";
    public static final String PACKAGE_WEBSERVICE = "checkout.errors.package.webservice";
    public static final String PACKAGE_STATUS_NOT_FOUND = "checkout.errors.package.status.not.found";
    public static final String ANONYMOUS_USER_NOT_FOUND = "checkout.errors.anonymous.user.not.found";

    public BusinessException(String code) {
        super(code);
    }

    public BusinessException(String code, Exception ex) {
        super(code, ex);
    }
}
