package seedu.address.logic;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import seedu.address.logic.parser.Prefix;
import seedu.address.model.person.Person;
import seedu.address.model.transaction.Transaction;

/**
 * Container for user visible messages.
 */
public class Messages {

    public static final String MESSAGE_UNKNOWN_COMMAND = "Unknown command";
    public static final String MESSAGE_INVALID_COMMAND_FORMAT = "Invalid command format! \n%1$s";
    public static final String MESSAGE_INVALID_PERSON_DISPLAYED_INDEX = "The person index provided is invalid";
    public static final String MESSAGE_INVALID_TRANSACTION_DISPLAYED_INDEX =
        "The transaction index provided is invalid";
    public static final String MESSAGE_PERSONS_LISTED_OVERVIEW = "%1$d persons listed!";
    public static final String MESSAGE_TRANSACTIONS_LISTED_OVERVIEW = "%1$d transactions listed!";
    public static final String MESSAGE_SHORTHAND_IS_COMMAND = "Cannot set shorthand %s as it is an existing command";
    public static final String MESSAGE_DUPLICATE_ALIAS = "Command alias %s is used for %s";
    public static final String MESSAGE_DUPLICATE_FIELDS =
        "Multiple values specified for the following single-valued field(s): ";

    /**
     * Returns an error message indicating the duplicate prefixes.
     */
    public static String getErrorMessageForDuplicatePrefixes(Prefix... duplicatePrefixes) {
        assert duplicatePrefixes.length > 0;

        Set<String> duplicateFields =
            Stream.of(duplicatePrefixes).map(Prefix::toString).collect(Collectors.toSet());

        return MESSAGE_DUPLICATE_FIELDS + String.join(" ", duplicateFields);
    }

    /**
     * Formats the {@code person} for display to the user.
     */
    public static String format(Person person) {
        final StringBuilder builder = new StringBuilder();
        builder.append(person.getName());
        if (person.getPhone() != null) {
            builder.append("; Phone: ")
                    .append(person.getPhone());
        }
        if (person.getTelegramHandle() != null) {
            builder.append("; Telegram Handle: ")
                    .append(person.getTelegramHandle());
        }
        if (person.getEmail() != null) {
            builder.append("; Email: ")
                    .append(person.getEmail());
        }
        if (person.getAddress() != null) {
            builder.append("; Address: ")
                    .append(person.getAddress());
        }
        if (person.getTags().size() > 0) {
            builder.append("; Tags: ");
            person.getTags().forEach(builder::append);
        }
        return builder.toString();
    }

    /**
     * Formats the {@code transaction} for display to the user.
     */
    public static String format(Transaction transaction, boolean includeTimestamp) {
        final StringBuilder builder = new StringBuilder();
        builder.append(transaction.getDescription());
        if (includeTimestamp) {
            builder.append("; Timestamp: ")
                .append(transaction.getTimestamp());
        }
        builder.append("; Amount: ")
            .append(transaction.getAmount())
            .append("; Paid by: ")
            .append(transaction.getPayeeName())
            .append("; Portions: ");
        transaction.getPortions().forEach(builder::append);
        return builder.toString();
    }
}
