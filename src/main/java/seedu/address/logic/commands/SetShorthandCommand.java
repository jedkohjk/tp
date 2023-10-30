package seedu.address.logic.commands;

import static seedu.address.logic.parser.CliSyntax.PREFIX_ORIGINAL_COMMAND;
import static seedu.address.logic.parser.CliSyntax.PREFIX_SHORTHAND;

import seedu.address.commons.util.ToStringBuilder;
import seedu.address.logic.commands.exceptions.CommandException;
import seedu.address.model.Model;

/**
 * Sets shorthand for a command.
 */
public class SetShorthandCommand extends Command {
    public static final String COMMAND_WORD = "setShorthand";

    public static final String MESSAGE_SET_SHORTHAND_SUCCESS = "Shorthand %s set for command %s";
    public static final String MESSAGE_UPDATE_SHORTHAND_SUCCESS = "Shorthand for command %s updated from %s to %s";

    public static final String MESSAGE_USAGE = COMMAND_WORD + ": Sets an alias for command words. "
        + "Parameters: "
        + PREFIX_ORIGINAL_COMMAND + "COMMAND "
        + PREFIX_SHORTHAND + "SHORTHAND "
        + "Example: " + COMMAND_WORD + " "
        + PREFIX_ORIGINAL_COMMAND + "addTransaction "
        + PREFIX_SHORTHAND + "addT";

    private final String original;
    private final String alias;

    /**
     * Constructs a SetShorthandCommand.
     */
    public SetShorthandCommand(String original, String alias) {
        this.original = original;
        this.alias = alias;
    }

    @Override
    public CommandResult execute(Model model) throws CommandException {
        String prevAlias = model.setCommandAlias(original, alias);
        if (prevAlias == null) {
            return new CommandResult(String.format(MESSAGE_SET_SHORTHAND_SUCCESS, alias, original));
        }
        return new CommandResult(String.format(MESSAGE_UPDATE_SHORTHAND_SUCCESS, original, prevAlias, alias));
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }

        // instanceof handles nulls
        if (!(other instanceof SetShorthandCommand)) {
            return false;
        }

        SetShorthandCommand otherCommand = (SetShorthandCommand) other;
        return original.equals(otherCommand.original) && alias.equals(otherCommand.alias);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
            .add("original", original)
            .add("shorthand", alias)
            .toString();
    }
}
