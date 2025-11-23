create table user(
    id     int          primary key auto_increment,
    name   varchar(100) not null,
    email  varchar(100) unique not null,
    profile_url varchar(255),
    created_at timestamp default current_timestamp,
    updated_at timestamp default current_timestamp on update current_timestamp
);

create table labs (
    id       int          primary key auto_increment,
    name       varchar(100) not null,
    location   varchar(100) not null,
    created_at timestamp default current_timestamp,
    updated_at timestamp default current_timestamp on update current_timestamp
);

create table devices (
    id          int          primary key auto_increment,
    lab_id      int,
    user_id     int,
    device_name varchar(100) not null,
    lab_location varchar(100),
    device_type varchar(100) not null, -- laptop, desktop, server, etc.
    status      varchar(50)  not null, -- available, in-use, maintenance, etc.
    price       decimal(10,2) not null,
    ram        int, -- in GB
    storage     int, -- in GB
    cpu         varchar(100),
    gpu         varchar(100),
    last_maintenance_date date,
    ink_levels  int, -- for printers
    display_size float, -- in inches
    created_at  timestamp default current_timestamp,
    updated_at  timestamp default current_timestamp on update current_timestamp,
    foreign key (lab_id) references labs(id)
);
