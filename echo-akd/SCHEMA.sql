CREATE TABLE akd_azks (
    id INT2 PRIMARY KEY
        CHECK (id = 1),
    latest_epoch INT8 NOT NULL
        CHECK (latest_epoch >= 0),
    num_nodes INT8 NOT NULL
        CHECK (num_nodes >= 0)
);

INSERT INTO akd_azks (id, latest_epoch, num_nodes) VALUES (1, 0, 0);

CREATE TYPE "NodeType" AS ENUM(
    'Leaf',
    'Root',
    'Interior'
);

CREATE TABLE akd_tree_nodes (
    label BYTEA NOT NULL
        CHECK (length(label) <= 32),
    last_epoch INT8 NOT NULL
        CHECK (last_epoch >= 0),
    min_descendant_epoch INT8 NOT NULL
        CHECK (min_descendant_epoch >= 0),
    parent BYTEA NOT NULL,
    node_type "NodeType",
    left_child BYTEA,
    right_child BYTEA,
    hash BYTEA NOT NULL
        CHECK (length(hash) = 32),

    PRIMARY KEY (label, last_epoch)
);

INSERT INTO akd_tree_nodes (
    label,
    last_epoch,
    min_descendant_epoch,
    parent,
    node_type,
    left_child,
    right_child,
    hash
)
VALUES (
    '\x', 0, 0, '\x', 'Root'::"NodeType", NULL, NULL,
    '\x0000000000000000000000000000000000000000000000000000000000000000'
);

CREATE TABLE akd_value_states (
    username BYTEA NOT NULL,
    epoch INT8 NOT NULL
        CHECK (epoch >= 0),
    label BYTEA NOT NULL,
    version INT8 NOT NULL
        CHECK (version >= 0),
    value BYTEA NOT NULL,

    PRIMARY KEY (username, epoch)
);
