package seedu.address.logic.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static seedu.address.logic.commands.CommandTestUtil.DESC_DINNER;
import static seedu.address.logic.commands.CommandTestUtil.DESC_LUNCH;
import static seedu.address.logic.commands.CommandTestUtil.assertTransactionCommandSuccess;
import static seedu.address.logic.commands.CommandTestUtil.showTransactionAtIndex;
import static seedu.address.logic.commands.EditTransactionCommand.MESSAGE_TRANSACTION_NOT_RELEVANT;
import static seedu.address.testutil.TypicalAddressBook.getTypicalAddressBook;
import static seedu.address.testutil.TypicalIndexes.INDEX_FIRST_ELEMENT;
import static seedu.address.testutil.TypicalIndexes.INDEX_SECOND_ELEMENT;

import org.junit.jupiter.api.Test;

import seedu.address.commons.core.index.Index;
import seedu.address.logic.Messages;
import seedu.address.logic.commands.EditTransactionCommand.EditTransactionDescriptor;
import seedu.address.model.AddressBook;
import seedu.address.model.Model;
import seedu.address.model.ModelManager;
import seedu.address.model.UserPrefs;
import seedu.address.model.transaction.Transaction;
import seedu.address.testutil.EditTransactionDescriptorBuilder;
import seedu.address.testutil.TransactionBuilder;



/**
 * Contains integration tests (interaction with the Model) and unit tests for EditTransactionCommand.
 */
class EditTransactionCommandTest {

    private Model model = new ModelManager(getTypicalAddressBook(), new UserPrefs());

    @Test
    public void execute_allFieldsSpecifiedUnfilteredList_success() {
        Transaction originalTransaction = model.getFilteredTransactionList().get(0);
        Transaction editedTransaction = new TransactionBuilder()
                .withPayeeName(originalTransaction.getPayeeName().toString())
                .withTimestamp(originalTransaction.getTimestamp().toString())
                .withPortions(originalTransaction.getPortions()).build();
        EditTransactionDescriptor descriptor = new EditTransactionDescriptorBuilder(editedTransaction).build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT, descriptor);

        String expectedMessage = String.format(
                EditTransactionCommand.MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true));
        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()), new UserPrefs());

        expectedModel.setTransaction(model.getFilteredTransactionList().get(0), editedTransaction);

        assertTransactionCommandSuccess(editTransactionCommand, model, expectedMessage, expectedModel);
    }

    @Test
    public void execute_descriptionFieldSpecifiedUnfilteredList_success() {
        Transaction firstTransaction = model.getFilteredTransactionList().get(INDEX_FIRST_ELEMENT.getZeroBased());
        String descriptionString = "A New Dinner";

        TransactionBuilder transactionInList = new TransactionBuilder(firstTransaction);
        Transaction editedTransaction = transactionInList.withDescription(descriptionString).build();

        EditTransactionDescriptor descriptor = new EditTransactionDescriptorBuilder()
                .withDescription(descriptionString).build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT, descriptor);

        String expectedMessage = String.format(
                EditTransactionCommand.MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true));
        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()), new UserPrefs());

        expectedModel.setTransaction(model.getFilteredTransactionList().get(0), editedTransaction);

        assertTransactionCommandSuccess(editTransactionCommand, model, expectedMessage, expectedModel);
    }

    @Test
    public void execute_costFieldSpecifiedUnfilteredList_success() {
        Transaction firstTransaction = model.getFilteredTransactionList().get(INDEX_FIRST_ELEMENT.getZeroBased());
        String costString = "123.21";

        TransactionBuilder transactionInList = new TransactionBuilder(firstTransaction);
        Transaction editedTransaction = transactionInList.withAmount(costString).build();

        EditTransactionDescriptor descriptor = new EditTransactionDescriptorBuilder()
                .withAmount(costString).build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT, descriptor);

        String expectedMessage = String.format(
                EditTransactionCommand.MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true));
        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()), new UserPrefs());

        expectedModel.setTransaction(model.getFilteredTransactionList().get(0), editedTransaction);

        assertTransactionCommandSuccess(editTransactionCommand, model, expectedMessage, expectedModel);
    }

    @Test
    public void execute_timestampFieldSpecifiedUnfilteredList_success() {
        Transaction firstTransaction = model.getFilteredTransactionList().get(INDEX_FIRST_ELEMENT.getZeroBased());
        String timestampString = "10/10/2020 10:10";

        TransactionBuilder transactionInList = new TransactionBuilder(firstTransaction);
        Transaction editedTransaction = transactionInList.withTimestamp(timestampString).build();

        EditTransactionDescriptor descriptor = new EditTransactionDescriptorBuilder()
                .withTimestamp(timestampString).build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT, descriptor);

        String expectedMessage = String.format(
                EditTransactionCommand.MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true));
        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()), new UserPrefs());

        expectedModel.setTransaction(model.getFilteredTransactionList().get(0), editedTransaction);

        assertTransactionCommandSuccess(editTransactionCommand, model, expectedMessage, expectedModel);
    }

    @Test
    public void execute_noFieldSpecifiedUnfilteredList_success() {
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT,
                new EditTransactionDescriptor());
        Transaction editedTransaction = model.getFilteredTransactionList().get(INDEX_FIRST_ELEMENT.getZeroBased());

        String expectedMessage = String.format(
                EditTransactionCommand.MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true));
        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()), new UserPrefs());

        expectedModel.setTransaction(model.getFilteredTransactionList().get(0), editedTransaction);

        assertTransactionCommandSuccess(editTransactionCommand, model, expectedMessage, expectedModel);
    }

    @Test
    public void execute_invalidTransactionUnfilteredList_failure() {
        EditTransactionDescriptor descriptor = new EditTransactionDescriptorBuilder()
                .withPayeeName("Alice").build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT, descriptor);

        CommandTestUtil.assertCommandFailure(editTransactionCommand, model,
                MESSAGE_TRANSACTION_NOT_RELEVANT);
    }

    @Test
    public void execute_filteredList_success() {
        showTransactionAtIndex(model, INDEX_FIRST_ELEMENT);

        Transaction transactionInFilteredList = model.getFilteredTransactionList()
                .get(INDEX_FIRST_ELEMENT.getZeroBased());
        Transaction editedTransaction = new TransactionBuilder(transactionInFilteredList)
                .withAmount("123.21").build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(INDEX_FIRST_ELEMENT,
                new EditTransactionDescriptorBuilder().withAmount("123.21").build());

        String expectedMessage = String.format(
                EditTransactionCommand.MESSAGE_EDIT_TRANSACTION_SUCCESS, Messages.format(editedTransaction, true));

        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()), new UserPrefs());
        expectedModel.setTransaction(model.getFilteredTransactionList().get(0), editedTransaction);

        assertTransactionCommandSuccess(editTransactionCommand, model, expectedMessage, expectedModel);
    }

    @Test
    public void execute_invalidTransactionIndexUnfilteredList_failure() {
        Index outOfBoundIndex = Index.fromOneBased(model.getFilteredTransactionList().size() + 1);
        EditTransactionDescriptor descriptor = new EditTransactionDescriptorBuilder()
                .withAmount("123.21").build();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(outOfBoundIndex, descriptor);

        CommandTestUtil.assertCommandFailure(editTransactionCommand, model,
                Messages.MESSAGE_INVALID_TRANSACTION_DISPLAYED_INDEX);
    }

    /**
     * Edit filtered list where index is larger than size of filtered list,
     * but smaller than size of address book
     */
    @Test
    public void execute_invalidTransactionIndexFilteredList_failure() {
        showTransactionAtIndex(model, INDEX_FIRST_ELEMENT);
        Index outOfBoundIndex = INDEX_SECOND_ELEMENT;
        // ensures that outOfBoundIndex is still in bounds of address book list
        assertTrue(outOfBoundIndex.getZeroBased() < model.getAddressBook().getTransactionList().size());

        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(outOfBoundIndex,
                new EditTransactionDescriptorBuilder().withAmount("123.21").build());

        CommandTestUtil.assertCommandFailure(editTransactionCommand, model,
                Messages.MESSAGE_INVALID_TRANSACTION_DISPLAYED_INDEX);
    }

    @Test
    public void equals() {
        final EditTransactionCommand standardCommand = new EditTransactionCommand(
                INDEX_FIRST_ELEMENT, DESC_LUNCH);

        // same values -> returns true
        EditTransactionDescriptor copyDescriptor = new EditTransactionDescriptor(DESC_LUNCH);
        EditTransactionCommand commandWithSameValues = new EditTransactionCommand(INDEX_FIRST_ELEMENT,
                copyDescriptor);
        assertTrue(standardCommand.equals(commandWithSameValues));

        // same object -> returns true
        assertTrue(standardCommand.equals(standardCommand));

        // null -> returns false
        assertFalse(standardCommand.equals(null));

        // different types -> returns false
        assertFalse(standardCommand.equals(new ClearCommand()));

        // different index -> returns false
        assertFalse(standardCommand.equals(new EditTransactionCommand(INDEX_SECOND_ELEMENT, DESC_LUNCH)));

        // different descriptor -> returns false
        assertFalse(standardCommand.equals(new EditTransactionCommand(INDEX_FIRST_ELEMENT, DESC_DINNER)));
    }

    @Test
    public void toStringMethod() {
        Index index = INDEX_FIRST_ELEMENT;
        EditTransactionDescriptor editTransactionDescriptor = new EditTransactionDescriptor();
        EditTransactionCommand editTransactionCommand = new EditTransactionCommand(index, editTransactionDescriptor);
        String expectedString = EditTransactionCommand.class.getCanonicalName()
                + "{index=" + index
                + ", editTransactionDescriptor=" + editTransactionDescriptor + "}";
        assertEquals(expectedString, editTransactionCommand.toString());
    }
}
