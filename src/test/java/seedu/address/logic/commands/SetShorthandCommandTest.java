package seedu.address.logic.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static seedu.address.logic.commands.CommandTestUtil.assertTransactionCommandSuccess;
import static seedu.address.testutil.TypicalAddressBook.getTypicalAddressBook;

import org.junit.jupiter.api.Test;

import seedu.address.logic.commands.exceptions.CommandException;
import seedu.address.model.AddressBook;
import seedu.address.model.Model;
import seedu.address.model.ModelManager;
import seedu.address.model.UserPrefs;

public class SetShorthandCommandTest {

    private Model model = new ModelManager(getTypicalAddressBook(), new UserPrefs());

    @Test
    public void execute() {
        Model expectedModel = new ModelManager(new AddressBook(model.getAddressBook()),
                new UserPrefs(model.getUserPrefs()));
        try {
            expectedModel.setCommandAlias(SetShorthandCommand.COMMAND_WORD, "a");
        } catch (CommandException e) {
            assertTrue(false);
        }
        SetShorthandCommand cmd = new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "a");
        String expectedMessage = String.format(SetShorthandCommand.MESSAGE_SET_SHORTHAND_SUCCESS,
                "a", SetShorthandCommand.COMMAND_WORD);
        assertTransactionCommandSuccess(cmd, model, expectedMessage, expectedModel);
        try {
            expectedModel.setCommandAlias(SetShorthandCommand.COMMAND_WORD, "b");
        } catch (CommandException e) {
            assertTrue(false);
        }
        cmd = new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "b");
        expectedMessage = String.format(SetShorthandCommand.MESSAGE_UPDATE_SHORTHAND_SUCCESS,
                SetShorthandCommand.COMMAND_WORD, "a", "b");
        assertTransactionCommandSuccess(cmd, model, expectedMessage, expectedModel);
    }

    @Test
    public void equals() {
        SetShorthandCommand commandShorthandA = new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "a");
        SetShorthandCommand commandShorthandB = new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "b");
        SetShorthandCommand commandShorthandACopy = new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "a");

        // same object -> returns true
        assertTrue(commandShorthandA.equals(commandShorthandA));

        // same values -> returns true
        assertTrue(commandShorthandA.equals(commandShorthandACopy));

        // different types -> returns false
        assertFalse(commandShorthandA.equals(1));

        // null -> returns false
        assertFalse(commandShorthandA.equals(null));

        // different person -> returns false
        assertFalse(commandShorthandA.equals(commandShorthandB));
    }

    @Test
    public void toStringMethod() {
        SetShorthandCommand commandShorthand = new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "a");
        String expected = SetShorthandCommand.class.getCanonicalName()
                + "{original=" + SetShorthandCommand.COMMAND_WORD + ", " + "shorthand=" + "a" + "}";
        assertEquals(expected, commandShorthand.toString());
    }
}
