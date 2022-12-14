const { Op, where } = require("sequelize");
const { CreateUserToken: CreateUserToken } = require("../models/UserTokens.model");
const dbConnection = require("./dbConnection");

const  UserToken = CreateUserToken(dbConnection.connection, dbConnection.DataTypes);

exports.addUserToken = async (userToken) => {
    return await UserToken.create({
        username : userToken.username,
        refreshToken : userToken.refreshToken,
        //expiresAt : Date.now() + (24*60*60*1000*10)
    });
}

exports.isValidUserToken = async (userToken) => {
    const storedUserToken = await UserToken.findOne({
        where : {
            [Op.and] : [
                {
                    username : userToken.username
                },
                {
                    refreshToken : userToken.refreshToken
                }
            ]
        }
    })
    return !storedUserToken ? false : true;
}

exports.createUserTokenTable = async() => {
    await UserToken.sync({force : false});
}