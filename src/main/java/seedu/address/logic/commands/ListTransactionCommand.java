package seedu.address.logic.commands;

import static java.util.Objects.requireNonNull;
import static seedu.address.logic.parser.CliSyntax.PREFIX_NAME;
import static seedu.address.model.Model.PREDICATE_SHOW_ALL_TRANSACTIONS;

import seedu.address.commons.util.ToStringBuilder;
import seedu.address.logic.Messages;
import seedu.address.model.Model;
import seedu.address.model.transaction.TransactionContainsPersonNamesPredicate;

/**
 * List all transactions that involve some specified persons, either as a payer or a payee.
 * If no persons are specified, list all transactions.
 */
public class ListTransactionCommand extends Command {

    public static final String COMMAND_WORD = "listTransaction";

    public static final String MESSAGE_USAGE = COMMAND_WORD + ": Lists all transactions that involve some specified "
        + "persons, either as a payer or a payee. If no persons are specified, list all transactions. "
        + "Parameters: "
        + "[" + PREFIX_NAME + "NAME]...\n"
        + "Example: " + COMMAND_WORD + " "
        + PREFIX_NAME + "John Doe ";

    private final TransactionContainsPersonNamesPredicate predicate;

    public ListTransactionCommand(TransactionContainsPersonNamesPredicate predicate) {
        this.predicate = predicate;
    }

    @Override
    public CommandResult execute(Model model) {
        requireNonNull(model);
        if (predicate.isEmpty()) {
            model.updateFilteredTransactionList(PREDICATE_SHOW_ALL_TRANSACTIONS);
        } else {
            model.updateFilteredTransactionList(predicate);
        }
        return new CommandResult(
            String.format(Messages.MESSAGE_TRANSACTIONS_LISTED_OVERVIEW, model.getFilteredTransactionList().size()));
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }

        // instanceof handles nulls
        if (!(other instanceof ListTransactionCommand)) {
            return false;
        }

        ListTransactionCommand otherFindCommand = (ListTransactionCommand) other;
        return predicate.equals(otherFindCommand.predicate);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
            .add("predicate", predicate)
            .toString();
    }
}
