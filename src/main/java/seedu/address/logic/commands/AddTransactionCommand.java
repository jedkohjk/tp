package seedu.address.logic.commands;

import static java.util.Objects.requireNonNull;
import static seedu.address.logic.parser.CliSyntax.PREFIX_COST;
import static seedu.address.logic.parser.CliSyntax.PREFIX_DESCRIPTION;
import static seedu.address.logic.parser.CliSyntax.PREFIX_NAME;
import static seedu.address.logic.parser.CliSyntax.PREFIX_TIMESTAMP;
import static seedu.address.logic.parser.CliSyntax.PREFIX_WEIGHT;

import seedu.address.commons.util.ToStringBuilder;
import seedu.address.logic.Messages;
import seedu.address.logic.commands.exceptions.CommandException;
import seedu.address.model.Model;
import seedu.address.model.transaction.Transaction;


/**
 * Adds a transaction to the address book.
 */
public class AddTransactionCommand extends Command {

    public static final String COMMAND_WORD = "addTransaction";

    public static final String MESSAGE_USAGE = COMMAND_WORD + ": Adds a transaction to the address book. \n"
            + "Parameters: "
            + PREFIX_DESCRIPTION + "DESCRIPTION "
            + PREFIX_NAME + "NAME "
            + PREFIX_COST + "COST "
            + "["
            + PREFIX_TIMESTAMP + "TIME"
            + "] "
            + "["
            + PREFIX_NAME + "NAME "
            + PREFIX_WEIGHT + "WEIGHT"
            + "]... "
            + "Example: " + COMMAND_WORD + " "
            + PREFIX_DESCRIPTION + "bread "
            + PREFIX_NAME + "John Doe "
            + PREFIX_COST + "25.00 "
            + PREFIX_TIMESTAMP + "10/10/2020 12:00 "
            + PREFIX_NAME + "Self "
            + PREFIX_WEIGHT + "1.5 "
            + PREFIX_NAME + "John Doe "
            + PREFIX_WEIGHT + "1";

    public static final String MESSAGE_SUCCESS = "New transaction added: %1$s";

    public static final String MESSAGE_DUPLICATE_TRANSACTION = "This transaction already exists in the address book";
    public static final String MESSAGE_IRRELEVANT_TRANSACTION = "This transaction does not affect your balances";
    public static final String MESSAGE_UNKNOWN_PARTY =
            "This transaction involves unknown parties; please set them to 'Others'";

    private final Transaction toAdd;

    /**
     * Creates an AddCommand to add the specified {@code Transaction}.
     */
    public AddTransactionCommand(Transaction transaction) {
        requireNonNull(transaction);
        toAdd = transaction;
    }

    @Override
    public CommandResult execute(Model model) throws CommandException {
        requireNonNull(model);

        if (!toAdd.isRelevant()) {
            throw new CommandException(MESSAGE_IRRELEVANT_TRANSACTION);
        }

        if (!toAdd.isKnown(model.getAllNames())) {
            throw new CommandException(MESSAGE_UNKNOWN_PARTY);
        }

        if (model.hasTransaction(toAdd)) {
            throw new CommandException(MESSAGE_DUPLICATE_TRANSACTION);
        }

        model.addTransaction(toAdd);
        return new CommandResult(String.format(MESSAGE_SUCCESS, Messages.format(toAdd, true)));
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }

        // instanceof handles nulls
        if (!(other instanceof AddTransactionCommand)) {
            return false;
        }

        AddTransactionCommand otherAddTransactionCommand = (AddTransactionCommand) other;
        return toAdd.equals(otherAddTransactionCommand.toAdd);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .add("toAdd", toAdd)
                .toString();
    }

}
