import Mock from 'mockjs';

const LoginUsers = [
  {
    id: 1,
    username: 'admin',
    password: '123456',
    name: 'Admin User'
  }
];

const Users = [];

for (let i = 0; i < 86; i++) {
  Users.push(Mock.mock({
    id: Mock.Random.guid(),
    name: Mock.Random.name(),
    grade: Mock.Random.integer(0,2100),
    phone: Mock.Random.integer(13100000000,13199999999),
    group: 'Backend Frontend',
    power: Mock.Random.paragraph(),
    pub_data: Mock.Random.date()
  }));
}

export { LoginUsers, Users };
