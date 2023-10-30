package seedu.address.logic.parser;

/**
 * Contains Command Line Interface (CLI) syntax definitions common to multiple commands
 */
public class CliSyntax {

    /* Prefix definitions */
    public static final Prefix PREFIX_NAME = new Prefix("n=");
    public static final Prefix PREFIX_PHONE = new Prefix("p=");
    public static final Prefix PREFIX_TELEGRAM_HANDLE = new Prefix("tg=");
    public static final Prefix PREFIX_EMAIL = new Prefix("e=");
    public static final Prefix PREFIX_ADDRESS = new Prefix("a=");
    public static final Prefix PREFIX_TAG = new Prefix("t=");
    public static final Prefix PREFIX_COST = new Prefix("c=");
    public static final Prefix PREFIX_DESCRIPTION = new Prefix("d=");
    public static final Prefix PREFIX_WEIGHT = new Prefix("w=");
    public static final Prefix PREFIX_ORIGINAL_COMMAND = new Prefix("o=");
    public static final Prefix PREFIX_SHORTHAND = new Prefix("s=");

    public static final Prefix PREFIX_TIMESTAMP = new Prefix("ts=");

}
