package seedu.address.logic.commands;

import static java.util.Objects.requireNonNull;
import static seedu.address.logic.parser.CliSyntax.PREFIX_COST;
import static seedu.address.logic.parser.CliSyntax.PREFIX_DESCRIPTION;
import static seedu.address.logic.parser.CliSyntax.PREFIX_NAME;
import static seedu.address.logic.parser.CliSyntax.PREFIX_TIMESTAMP;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import seedu.address.commons.core.index.Index;
import seedu.address.commons.util.CollectionUtil;
import seedu.address.commons.util.ToStringBuilder;
import seedu.address.logic.Messages;
import seedu.address.logic.commands.exceptions.CommandException;
import seedu.address.model.Model;
import seedu.address.model.person.Name;
import seedu.address.model.transaction.Amount;
import seedu.address.model.transaction.Description;
import seedu.address.model.transaction.Timestamp;
import seedu.address.model.transaction.Transaction;
import seedu.address.model.transaction.portion.Portion;

/**
 * Edits the details of an existing transaction in the transaction list.
 * i.e. cost, description, payeeName
 * Note: Editing of expenses is done via the {@code UpdatePortionCommand}.
 */
public class EditTransactionCommand extends Command {

    public static final String COMMAND_WORD = "editTransaction";

    public static final String MESSAGE_USAGE = COMMAND_WORD + ": Edits the details of the transaction identified "
            + "by the index number used in the displayed transaction list. "
            + "Existing values will be overwritten by the input values.\n"
            + "Parameters: INDEX (must be a positive integer) "
            + "[" + PREFIX_COST + "COST] "
            + "[" + PREFIX_DESCRIPTION + "DETAILS] "
            + "[" + PREFIX_TIMESTAMP + "TIME] "
            + "[" + PREFIX_NAME + "PAYEE NAME] "
            + "[" + PREFIX_TIMESTAMP + "TIMESTAMP] "
            + "Example: " + COMMAND_WORD + " 1 "
            + PREFIX_COST + "10.00 "
            + PREFIX_DESCRIPTION + "Bought a book "
            + PREFIX_NAME + "John Doe "
            + PREFIX_TIMESTAMP + "10/10/2020 12:00";

    public static final String MESSAGE_EDIT_TRANSACTION_SUCCESS = "Edited Transaction: %1$s";

    public static final String MESSAGE_TRANSACTION_NOT_EDITED = "At least one field to edit must be provided.";

    public static final String MESSAGE_TRANSACTION_NOT_RELEVANT =
            "The edited transaction does not affect your balances. Please use the delete command instead.";

    private final Index index;

    private final EditTransactionDescriptor editTransactionDescriptor;

    /**
     * @param index of the transaction in the filtered transaction list to edit
     * @param editTransactionDescriptor details to edit the transaction with
     */
    public EditTransactionCommand(Index index, EditTransactionDescriptor editTransactionDescriptor) {
        requireNonNull(index);
        requireNonNull(editTransactionDescriptor);

        this.index = index;
        this.editTransactionDescriptor = new EditTransactionDescriptor(editTransactionDescriptor);
    }

    @Override
    public CommandResult execute(Model model) throws CommandException {
        requireNonNull(model);
        List<Transaction> lastShownTransactionList = model.getFilteredTransactionList();

        if (index.getZeroBased() >= lastShownTransactionList.size()) {
            throw new CommandException(Messages.MESSAGE_INVALID_TRANSACTION_DISPLAYED_INDEX);
        }

        Transaction transactionToEdit = lastShownTransactionList.get(index.getZeroBased());
        Transaction editedTransaction = createEditedTransaction(transactionToEdit, editTransactionDescriptor);

        if (!editedTransaction.isRelevant()) {
            throw new CommandException(MESSAGE_TRANSACTION_NOT_RELEVANT);
        }

        model.setTransaction(transactionToEdit, editedTransaction);
        model.updateFilteredTransactionList(Model.PREDICATE_SHOW_ALL_TRANSACTIONS);
        return new CommandResult(
                String.format(MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true)));

    }
    /**
     * Creates and returns a {@code Transaction} with the details of {@code transactionToEdit}
     * edited with {@code editTransactionDescriptor}.
     * Portions are not edited with this {@code EditTransactionCommand}
     */
    private static Transaction createEditedTransaction(Transaction transactionToEdit, EditTransactionDescriptor
            editTransactionDescriptor) {
        assert transactionToEdit != null;

        Amount updatedAmount = editTransactionDescriptor.getAmount().orElse(transactionToEdit.getAmount());
        Description updatedDescription = editTransactionDescriptor.getDescription().orElse(transactionToEdit
                .getDescription());
        Name updatedPayeeName = editTransactionDescriptor.getPayeeName().orElse(transactionToEdit.getPayeeName());
        Timestamp updatedTimestamp = editTransactionDescriptor.getTimestamp().orElse(transactionToEdit
                .getTimestamp());


        Set<Portion> existingPortions = transactionToEdit.getPortions();

        return new Transaction(updatedAmount, updatedDescription, updatedPayeeName, existingPortions, updatedTimestamp);
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }

        // instanceof handles nulls
        if (!(other instanceof EditTransactionCommand)) {
            return false;
        }

        EditTransactionCommand otherEditTransactionCommand = (EditTransactionCommand) other;
        return index.equals(otherEditTransactionCommand.index)
                && editTransactionDescriptor.equals(otherEditTransactionCommand.editTransactionDescriptor);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .add("index", index)
                .add("editTransactionDescriptor", editTransactionDescriptor)
                .toString();
    }

    /**
     * Stores the details to edit the transaction with. Each non-empty field value will replace the
     * corresponding field value of the transaction.
     * Note that "cost" is represented by {@code Amount} named {@code amount} in the model.
     * EditTransactionDescriptor does not edit and store portions.
     */
    public static class EditTransactionDescriptor {
        private Amount amount;
        private Description description;
        private Name payeeName;
        private Timestamp timestamp;

        public EditTransactionDescriptor() {}

        /**
         * Copy constructor.
         * A defensive copy of {@code portions} is used internally.
         */
        public EditTransactionDescriptor(EditTransactionDescriptor toCopy) {
            setAmount(toCopy.amount);
            setDescription(toCopy.description);
            setPayeeName(toCopy.payeeName);
            setTimestamp(toCopy.timestamp);
        }

        /**
         * Returns true if at least one field is edited.
         */
        public boolean isAnyFieldEdited() {
            return CollectionUtil.isAnyNonNull(amount, description, payeeName, timestamp);
        }

        public void setAmount(Amount amount) {
            this.amount = amount;
        }

        public Optional<Amount> getAmount() {
            return Optional.ofNullable(amount);
        }

        public void setDescription(Description description) {
            this.description = description;
        }

        public Optional<Description> getDescription() {
            return Optional.ofNullable(description);
        }

        public void setPayeeName(Name payeeName) {
            this.payeeName = payeeName;
        }

        public Optional<Name> getPayeeName() {
            return Optional.ofNullable(payeeName);
        }

        public void setTimestamp(Timestamp timestamp) {
            this.timestamp = timestamp;
        }

        public Optional<Timestamp> getTimestamp() {
            return Optional.ofNullable(timestamp);
        }

        @Override
        public boolean equals(Object other) {
            if (other == this) {
                return true;
            }

            // instanceof handles nulls
            if (!(other instanceof EditTransactionDescriptor)) {
                return false;
            }

            EditTransactionDescriptor otherEditTransactionDescriptor = (EditTransactionDescriptor) other;
            return Objects.equals(amount, otherEditTransactionDescriptor.amount)
                    && Objects.equals(description, otherEditTransactionDescriptor.description)
                    && Objects.equals(payeeName, otherEditTransactionDescriptor.payeeName)
                    && Objects.equals(timestamp, otherEditTransactionDescriptor.timestamp);
        }

        /**
         * Note that "cost" is represented by {@code Amount} named {@code amount} in the model.
         */
        @Override
        public String toString() {
            return new ToStringBuilder(this)
                    .add("timestamp", timestamp)
                    .add("cost", amount)
                    .add("description", description)
                    .add("payeeName", payeeName)
                    .toString();
        }
    }
}
