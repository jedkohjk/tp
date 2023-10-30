package seedu.address.logic.commands;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static seedu.address.testutil.Assert.assertThrows;
import static seedu.address.testutil.TypicalTransactions.LUNCH;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.function.Predicate;

import org.apache.commons.numbers.fraction.BigFraction;
import org.junit.jupiter.api.Test;

import javafx.collections.ObservableList;
import seedu.address.commons.core.GuiSettings;
import seedu.address.logic.Messages;
import seedu.address.logic.commands.exceptions.CommandException;
import seedu.address.logic.parser.CommandAliasMap;
import seedu.address.model.AddressBook;
import seedu.address.model.Model;
import seedu.address.model.ReadOnlyAddressBook;
import seedu.address.model.ReadOnlyUserPrefs;
import seedu.address.model.person.Name;
import seedu.address.model.person.Person;
import seedu.address.model.transaction.Transaction;
import seedu.address.testutil.TransactionBuilder;
import seedu.address.testutil.TypicalPersons;
import seedu.address.testutil.TypicalPortions;

public class AddTransactionCommandTest {

    @Test
    public void constructor_nullTransaction_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> new AddTransactionCommand(null));
    }

    @Test
    public void execute_transactionAcceptedByModel_addSuccessful() throws Exception {
        ModelStubAcceptingTransactionAdded modelStub = new ModelStubAcceptingTransactionAdded();
        Transaction validTransaction = new TransactionBuilder().build();
        CommandResult commandResult = new AddTransactionCommand(validTransaction).execute(modelStub);

        assertEquals(String.format(AddTransactionCommand.MESSAGE_SUCCESS, Messages.format(validTransaction, true)),
                commandResult.getFeedbackToUser());
        assertEquals(Arrays.asList(validTransaction), modelStub.transactionsAdded);
    }

    @Test
    public void execute_irrelevantTransaction_throwsCommandException() throws Exception {
        ModelStubAcceptingTransactionAdded modelStub = new ModelStubAcceptingTransactionAdded();
        Transaction irrelevantTransaction = new TransactionBuilder()
                .withPortions(Set.of(TypicalPortions.ALICE_PORTION)).build();
        AddTransactionCommand addTransactionCommand = new AddTransactionCommand(irrelevantTransaction);

        assertThrows(CommandException.class,
                AddTransactionCommand.MESSAGE_IRRELEVANT_TRANSACTION, () -> addTransactionCommand.execute(modelStub));
    }

    @Test
    public void execute_unknownTransaction_throwsCommandException() throws Exception {
        ModelStubAcceptingTransactionAdded modelStub = new ModelStubAcceptingTransactionAdded();
        Transaction irrelevantTransaction = new TransactionBuilder().withPayeeName("Unknown").build();
        AddTransactionCommand addTransactionCommand = new AddTransactionCommand(irrelevantTransaction);

        assertThrows(CommandException.class,
                AddTransactionCommand.MESSAGE_UNKNOWN_PARTY, () -> addTransactionCommand.execute(modelStub));
    }

    @Test
    public void execute_duplicateTransaction_throwsCommandException() {
        Transaction validTransaction = new TransactionBuilder().build();
        AddTransactionCommand addTransactionCommand = new AddTransactionCommand(validTransaction);
        ModelStub modelStub = new ModelStubWithTransaction(validTransaction);
        assertThrows(CommandException.class,
                AddTransactionCommand.MESSAGE_DUPLICATE_TRANSACTION, () -> addTransactionCommand.execute(modelStub));
    }

    @Test
    public void equals() {
        Transaction alice = new TransactionBuilder().withPayeeName("Alice").build();
        Transaction bob = new TransactionBuilder().withPayeeName("Bob").build();
        AddTransactionCommand addAliceCommand = new AddTransactionCommand(alice);
        AddTransactionCommand addBobCommand = new AddTransactionCommand(bob);

        // same object -> returns true
        assertTrue(addAliceCommand.equals(addAliceCommand));

        // same values -> returns true
        AddTransactionCommand addAliceCommandCopy = new AddTransactionCommand(alice);
        assertTrue(addAliceCommand.equals(addAliceCommandCopy));

        // different types -> returns false
        assertFalse(addAliceCommand.equals(1));

        // null -> returns false
        assertFalse(addAliceCommand.equals(null));

        // different person -> returns false
        assertFalse(addAliceCommand.equals(addBobCommand));
    }

    @Test
    public void toStringMethod() {
        AddTransactionCommand addTransactionCommand = new AddTransactionCommand(LUNCH);
        String expected = AddTransactionCommand.class.getCanonicalName() + "{toAdd=" + LUNCH + "}";
        assertEquals(expected, addTransactionCommand.toString());
    }

    /**
     * A default model stub that have all of the methods failing.
     */
    private class ModelStub implements Model {
        @Override
        public void setUserPrefs(ReadOnlyUserPrefs userPrefs) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public ReadOnlyUserPrefs getUserPrefs() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public GuiSettings getGuiSettings() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void setGuiSettings(GuiSettings guiSettings) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public Path getAddressBookFilePath() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void setAddressBookFilePath(Path addressBookFilePath) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void addPerson(Person person) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void addTransaction(Transaction transaction) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void setAddressBook(ReadOnlyAddressBook newData) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public ReadOnlyAddressBook getAddressBook() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public boolean hasPerson(Person person) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public boolean hasTransaction(Transaction transaction) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void deletePerson(Person target) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void deleteTransaction(Transaction target) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void setPerson(Person target, Person editedPerson) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void setTransaction(Transaction target, Transaction editedTransaction) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public BigFraction getBalance(Name name) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public ObservableList<Person> getFilteredPersonList() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public ObservableList<Transaction> getFullTransactionList() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public ObservableList<Transaction> getFilteredTransactionList() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void updateFilteredPersonList(Predicate<Person> predicate) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void updateFilteredTransactionList(Predicate<Transaction> predicate) {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public Set<Name> getAllNames() {
            return Set.of(TypicalPersons.ALICE.getName(), new TransactionBuilder().build().getPayeeName());
        }

        @Override
        public CommandAliasMap getCommandMap() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void sortPersonDescending() {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public String setCommandAlias(String command, String alias) throws CommandException {
            throw new AssertionError("This method should not be called.");
        }

        @Override
        public void sortPersonAscending() {
            throw new AssertionError("This method should not be called.");
        }
    }

    /**
     * A Model stub that contains a single transaction.
     */
    private class ModelStubWithTransaction extends ModelStub {
        private final Transaction transaction;

        ModelStubWithTransaction(Transaction transaction) {
            requireNonNull(transaction);
            this.transaction = transaction;
        }

        @Override
        public boolean hasTransaction(Transaction transaction) {
            requireNonNull(transaction);
            return this.transaction.isSameTransaction(transaction);
        }
    }

    /**
     * A Model stub that always accept the person being added.
     */
    private class ModelStubAcceptingTransactionAdded extends ModelStub {
        final ArrayList<Transaction> transactionsAdded = new ArrayList<>();

        @Override
        public boolean hasTransaction(Transaction transaction) {
            requireNonNull(transaction);
            return transactionsAdded.stream().anyMatch(transaction::isSameTransaction);
        }

        @Override
        public void addTransaction(Transaction transaction) {
            requireNonNull(transaction);
            transactionsAdded.add(transaction);
        }

        @Override
        public ReadOnlyAddressBook getAddressBook() {
            return new AddressBook();
        }
    }
}
