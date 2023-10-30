package seedu.address.testutil;


import static seedu.address.testutil.TypicalPortions.ALICE_PORTION;
import static seedu.address.testutil.TypicalPortions.SELF_PORTION;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import seedu.address.model.person.Name;
import seedu.address.model.transaction.Amount;
import seedu.address.model.transaction.Description;
import seedu.address.model.transaction.Timestamp;
import seedu.address.model.transaction.Transaction;
import seedu.address.model.transaction.portion.Portion;
import seedu.address.model.transaction.portion.Weight;

/**
 * A utility class to help with building Transaction objects.
 */
public class TransactionBuilder {

    public static final String DEFAULT_AMOUNT = "12.34";
    public static final String DEFAULT_DESCRIPTION = "Mala Xiang Guo at Clementi Mall on 12 Oct 2023";
    public static final String DEFAULT_PAYEE_NAME = "Default Payee Name";

    // necessary for testing of EditTransactionCommand, to test actual vs expected transactions
    public static final String DEFAULT_TIMESTAMP = "12/10/2023 12:34";

    public static final Set<Portion> DEFAULT_PORTIONS = new HashSet<>(
            List.of(new Portion(TypicalPersons.BOB.getName(), new Weight("1.0"))));

    private Amount amount;
    private Description description;
    private Name payeeName;
    private Set<Portion> portions;
    private Timestamp timestamp;

    /**
     * Creates a {@code TransactionBuilder} with the default details.
     */
    public TransactionBuilder() {
        amount = new Amount(DEFAULT_AMOUNT);
        description = new Description(DEFAULT_DESCRIPTION);
        payeeName = new Name(DEFAULT_PAYEE_NAME);
        portions = Set.of(ALICE_PORTION, SELF_PORTION);
        timestamp = Timestamp.now();
    }

    /**
     * Initializes the TransactionBuilder with the data of {@code transactionToCopy}.
     */
    public TransactionBuilder(Transaction transactionToCopy) {
        amount = transactionToCopy.getAmount();
        description = transactionToCopy.getDescription();
        payeeName = transactionToCopy.getPayeeName();
        portions = new HashSet<>(transactionToCopy.getPortions());
        timestamp = transactionToCopy.getTimestamp();
    }

    /**
     * Sets the {@code Amount} of the {@code Transaction} that we are building.
     */
    public TransactionBuilder withAmount(String amount) {
        this.amount = new Amount(amount);
        return this;
    }

    /**
     * Sets the {@code Description} of the {@code Transaction} that we are building.
     */
    public TransactionBuilder withDescription(String description) {
        this.description = new Description(description);
        return this;
    }

    /**
     * Sets the {@code PayeeName} of the {@code Transaction} that we are building.
     */
    public TransactionBuilder withPayeeName(String payeeName) {
        this.payeeName = new Name(payeeName);
        return this;
    }

    /**
     * Sets the {@code Portions} of the {@code Transaction} that we are building.
     */
    public TransactionBuilder withPortions(Set<Portion> portions) {
        this.portions = portions;
        return this;
    }

    /**
     * Sets the {@code LocalDateTime} of the {@code Transaction} that we are building.
     */
    public TransactionBuilder withTimestamp(String timestamp) {
        this.timestamp = new Timestamp(timestamp);
        return this;
    }

    public Transaction build() {
        return new Transaction(amount, description, payeeName, portions, timestamp);
    }
}
