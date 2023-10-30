package seedu.address.testutil;

import static seedu.address.testutil.TypicalPortions.ALICE_PORTION;
import static seedu.address.testutil.TypicalPortions.BENSON_PORTION;
import static seedu.address.testutil.TypicalPortions.SELF_PORTION;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.apache.commons.numbers.fraction.BigFraction;

import seedu.address.model.person.Name;
import seedu.address.model.transaction.Transaction;

/**
 * A utility class containing a list of {@code Transaction} objects to be used in tests.
 */
public class TypicalTransactions {
    public static final Transaction LUNCH = new TransactionBuilder().withAmount("60")
            .withDescription("Group Project Lunch").withPayeeName(Name.SELF.fullName)
            .withPortions(Set.of(ALICE_PORTION, BENSON_PORTION)).withTimestamp("13/10/2023 12:00").build();
    public static final Transaction DINNER = new TransactionBuilder().withAmount("90").withDescription("Hall Dinner")
            .withPayeeName(TypicalPersons.BENSON.getName().fullName)
            .withPortions(Set.of(BENSON_PORTION, SELF_PORTION)).withTimestamp("13/10/2023 16:00").build();


    public static final Transaction RENT = new TransactionBuilder().withAmount("600")
            .withDescription("Shared Dorm Rent").withPayeeName(TypicalPersons.BENSON.getName().fullName).withPortions(
                    Set.of(new PortionBuilder(BENSON_PORTION).withWeight(BigFraction.ONE.toString()).build(),
                           new PortionBuilder(SELF_PORTION).withWeight(BigFraction.ONE.toString()).build()))
            .withTimestamp("13/10/2023 13:00").build();

    public static final Transaction TRANSPORTATION = new TransactionBuilder().withAmount("100")
            .withDescription("Carpool Subscription").withPayeeName(Name.SELF.fullName).withPortions(
                    Set.of(new PortionBuilder(BENSON_PORTION).withWeight(BigFraction.ONE.toString()).build(),
                            new PortionBuilder(SELF_PORTION).withWeight(BigFraction.ONE.toString()).build()))
            .withTimestamp("13/10/2023 04:00").build();

    public static final Transaction GROCERIES = new TransactionBuilder().withAmount("120")
            .withDescription("Groceries").withPayeeName(Name.SELF.fullName).withPortions(
                    Set.of(new PortionBuilder(ALICE_PORTION).withWeight(BigFraction.ONE.toString()).build(),
                            new PortionBuilder(BENSON_PORTION).withWeight(BigFraction.ONE.toString()).build(),
                            new PortionBuilder(SELF_PORTION).withWeight(BigFraction.ONE.toString()).build()))
            .withTimestamp("13/10/2023 02:00").build();

    public static final Transaction BREAKFAST_WITH_ALICE = new TransactionBuilder().withAmount("10")
            .withDescription("Breakfast with Alice").withPayeeName(Name.SELF.fullName).withPortions(
                    Set.of(new PortionBuilder(ALICE_PORTION).withWeight("2.00").build()))
            .withTimestamp("14/10/2023 10:00").build();

    public static List<Transaction> getTypicalTransactions() {
        return new ArrayList<>(Arrays.asList(LUNCH, DINNER, RENT, TRANSPORTATION, BREAKFAST_WITH_ALICE));
    }
}
