// backend/server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { marked } = require('marked');
const DOMPurify = require('isomorphic-dompurify');
const NodeRSA = require('node-rsa');

// 环境变量配置
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const PORT = process.env.PORT || 5000;

// 初始化 Supabase 客户端
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// 创建 Express 应用
const app = express();

// 安全中间件
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// 限流中间件
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分钟
  max: 100 // 限制每个IP 15分钟内最多100个请求
});
app.use(limiter);

// JWT 验证中间件
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: '访问被拒绝' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: '无效的令牌' });
    }
    req.user = user;
    next();
  });
};

// 管理员验证中间件
const adminAuth = async (req, res, next) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('is_admin, is_main_admin')
      .eq('id', req.user.id)
      .single();

    if (error) {
      return res.status(403).json({ message: '数据库查询错误' });
    }

    if (!user.is_admin && !user.is_main_admin) {
      return res.status(403).json({ message: '需要管理员权限' });
    }

    req.isAdmin = user.is_admin;
    req.isMainAdmin = user.is_main_admin;
    next();
  } catch (err) {
    res.status(500).json({ message: '服务器错误' });
  }
};

// 主管理员验证中间件
const mainAdminAuth = async (req, res, next) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('is_main_admin')
      .eq('id', req.user.id)
      .single();

    if (error) {
      return res.status(403).json({ message: '数据库查询错误' });
    }

    if (!user.is_main_admin) {
      return res.status(403).json({ message: '需要主管理员权限' });
    }

    next();
  } catch (err) {
    res.status(500).json({ message: '服务器错误' });
  }
};

// 获取用户信息
const getUserInfo = async (userId) => {
  const { data, error } = await supabase
    .from('users')
    .select(`
      id, 
      username, 
      email, 
      vitality, 
      bio, 
      is_admin, 
      is_main_admin,
      created_at
    `)
    .eq('id', userId)
    .single();

  if (error) throw error;
  return data;
};

// 更新用户活力值
const updateVitality = async (userId, points) => {
  const { data: user, error: userError } = await supabase
    .from('users')
    .select('vitality')
    .eq('id', userId)
    .single();

  if (userError) throw userError;

  let newVitality = Math.max(0, user.vitality + points);
  
  const { error } = await supabase
    .from('users')
    .update({ vitality: newVitality })
    .eq('id', userId);

  if (error) throw error;
};

// 格式化帖子内容（Markdown + LaTeX）
const formatContent = (content) => {
  // 将LaTeX公式标记转换为MathJax兼容格式
  let formattedContent = content.replace(/\$\$(.*?)\$\$/g, '<div class="math">$$1</div>');
  formattedContent = formattedContent.replace(/\$(.*?)\$/g, '<span class="math-inline">$1</span>');
  
  // 使用marked解析Markdown
  const markdownContent = marked.parse(formattedContent);
  
  // 使用DOMPurify清理HTML
  return DOMPurify.sanitize(markdownContent);
};

// 获取帖子预览
const getPreview = (content, length = 100) => {
  const plainText = content.replace(/<[^>]*>/g, '');
  return plainText.length > length ? plainText.substring(0, length) + '...' : plainText;
};

// 路由定义

// 认证相关路由
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // 验证输入
    if (!username || !email || !password) {
      return res.status(400).json({ message: '所有字段都是必需的' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: '密码至少需要6个字符' });
    }

    // 检查用户名或邮箱是否已存在
    const { data: existingUser, error: existingError } = await supabase
      .from('users')
      .select('id')
      .or(`username.eq.${username},email.eq.${email}`)
      .single();

    if (existingUser) {
      return res.status(400).json({ message: '用户名或邮箱已存在' });
    }

    // 获取用户总数以确定是否为第一个用户（主管理员）
    const { count, error: countError } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });

    const isMainAdmin = count === 0; // 第一个注册的用户成为主管理员

    // 哈希密码
    const hashedPassword = await bcrypt.hash(password, 10);

    // 创建用户
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        username,
        email,
        password: hashedPassword,
        vitality: 0,
        is_admin: false,
        is_main_admin: isMainAdmin,
        bio: ''
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    // 生成JWT令牌
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        vitality: user.vitality,
        is_admin: user.is_admin,
        is_main_admin: user.is_main_admin
      }
    });
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ message: '注册失败' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 验证输入
    if (!username || !password) {
      return res.status(400).json({ message: '用户名和密码都是必需的' });
    }

    // 查找用户
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user) {
      return res.status(400).json({ message: '用户名或密码错误' });
    }

    // 验证密码
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: '用户名或密码错误' });
    }

    // 生成JWT令牌
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        vitality: user.vitality,
        is_admin: user.is_admin,
        is_main_admin: user.is_main_admin
      }
    });
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ message: '登录失败' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await getUserInfo(req.user.id);
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: '获取用户信息失败' });
  }
});

// 帖子相关路由
app.get('/api/posts', async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let query = supabase
      .from('posts')
      .select(`
        *,
        author:users(username, vitality, is_admin, is_main_admin)
      `, { count: 'exact' })
      .order('created_at', { ascending: false });

    if (search) {
      query = query.ilike('title', `%${search}%`);
    }

    const { data, error, count } = await query.range(offset, offset + limit - 1);

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    // 为每个帖子添加预览内容
    const postsWithPreview = data.map(post => ({
      ...post,
      preview: getPreview(post.content, 150)
    }));

    res.json({
      posts: postsWithPreview,
      total: count,
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    res.status(500).json({ message: '获取帖子列表失败' });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // 获取帖子详情
    const { data: post, error: postError } = await supabase
      .from('posts')
      .select(`
        *,
        author:users(username, vitality, is_admin, is_main_admin)
      `)
      .eq('id', id)
      .single();

    if (postError) {
      return res.status(404).json({ message: '帖子不存在' });
    }

    // 增加浏览数
    await supabase
      .from('posts')
      .update({ views_count: post.views_count + 1 })
      .eq('id', id);

    // 获取回复
    const { data: replies, error: repliesError } = await supabase
      .from('replies')
      .select(`
        *,
        author:users(username, vitality, is_admin, is_main_admin)
      `)
      .eq('post_id', id)
      .order('created_at', { ascending: true });

    if (repliesError) {
      return res.status(500).json({ message: repliesError.message });
    }

    res.json({
      post,
      replies
    });
  } catch (error) {
    res.status(500).json({ message: '获取帖子详情失败' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, category } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: '标题和内容不能为空' });
    }

    const formattedContent = formatContent(content);

    const { data: post, error } = await supabase
      .from('posts')
      .insert([{
        title,
        content: formattedContent,
        author_id: req.user.id,
        category: category || 'general'
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    // 增加用户活力值
    await updateVitality(req.user.id, 2);

    res.json(post);
  } catch (error) {
    res.status(500).json({ message: '发布帖子失败' });
  }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 检查是否已点赞
    const { data: existingLike, error: likeError } = await supabase
      .from('post_likes')
      .select('id')
      .eq('post_id', id)
      .eq('user_id', req.user.id)
      .single();

    if (existingLike) {
      return res.status(400).json({ message: '已点赞过' });
    }

    // 添加点赞记录
    const { error: insertError } = await supabase
      .from('post_likes')
      .insert([{ post_id: id, user_id: req.user.id }]);

    if (insertError) {
      return res.status(500).json({ message: insertError.message });
    }

    // 更新帖子点赞数
    const { error: updateError } = await supabase.rpc('update_post_likes_count', { post_id: id });

    if (updateError) {
      return res.status(500).json({ message: updateError.message });
    }

    // 增加帖子作者活力值
    const { data: post, error: postError } = await supabase
      .from('posts')
      .select('author_id')
      .eq('id', id)
      .single();

    if (postError) {
      return res.status(500).json({ message: postError.message });
    }

    await updateVitality(post.author_id, 2);

    res.json({ message: '点赞成功' });
  } catch (error) {
    res.status(500).json({ message: '点赞失败' });
  }
});

app.post('/api/posts/:id/useful', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 检查是否已标记为有用
    const { data: existingUseful, error: usefulError } = await supabase
      .from('post_useful')
      .select('id')
      .eq('post_id', id)
      .eq('user_id', req.user.id)
      .single();

    if (existingUseful) {
      return res.status(400).json({ message: '已标记过有用' });
    }

    // 添加有用记录
    const { error: insertError } = await supabase
      .from('post_useful')
      .insert([{ post_id: id, user_id: req.user.id }]);

    if (insertError) {
      return res.status(500).json({ message: insertError.message });
    }

    // 更新帖子有用数
    const { error: updateError } = await supabase.rpc('update_post_useful_count', { post_id: id });

    if (updateError) {
      return res.status(500).json({ message: updateError.message });
    }

    // 增加帖子作者活力值
    const { data: post, error: postError } = await supabase
      .from('posts')
      .select('author_id')
      .eq('id', id)
      .single();

    if (postError) {
      return res.status(500).json({ message: postError.message });
    }

    await updateVitality(post.author_id, 5);

    res.json({ message: '标记成功' });
  } catch (error) {
    res.status(500).json({ message: '标记失败' });
  }
});

// 回复相关路由
app.post('/api/posts/:id/replies', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ message: '回复内容不能为空' });
    }

    const formattedContent = formatContent(content);

    const { data: reply, error } = await supabase
      .from('replies')
      .insert([{
        post_id: id,
        content: formattedContent,
        author_id: req.user.id
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    // 增加用户活力值
    await updateVitality(req.user.id, 1);

    // 更新帖子回复数
    const { error: updateError } = await supabase.rpc('update_post_replies_count', { post_id: id });

    if (updateError) {
      return res.status(500).json({ message: updateError.message });
    }

    res.json(reply);
  } catch (error) {
    res.status(500).json({ message: '发布回复失败' });
  }
});

app.post('/api/replies/:id/like', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 检查是否已点赞
    const { data: existingLike, error: likeError } = await supabase
      .from('reply_likes')
      .select('id')
      .eq('reply_id', id)
      .eq('user_id', req.user.id)
      .single();

    if (existingLike) {
      return res.status(400).json({ message: '已点赞过' });
    }

    // 添加点赞记录
    const { error: insertError } = await supabase
      .from('reply_likes')
      .insert([{ reply_id: id, user_id: req.user.id }]);

    if (insertError) {
      return res.status(500).json({ message: insertError.message });
    }

    // 更新回复点赞数
    const { error: updateError } = await supabase.rpc('update_reply_likes_count', { reply_id: id });

    if (updateError) {
      return res.status(500).json({ message: updateError.message });
    }

    // 增加回复作者活力值
    const { data: reply, error: replyError } = await supabase
      .from('replies')
      .select('author_id')
      .eq('id', id)
      .single();

    if (replyError) {
      return res.status(500).json({ message: replyError.message });
    }

    await updateVitality(reply.author_id, 2);

    res.json({ message: '点赞成功' });
  } catch (error) {
    res.status(500).json({ message: '点赞失败' });
  }
});

// 用户相关路由
app.get('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: user, error } = await supabase
      .from('users')
      .select(`
        id, 
        username, 
        email, 
        vitality, 
        bio, 
        is_admin, 
        is_main_admin,
        created_at,
        followers:user_followers(count),
        following:user_following(count),
        posts:posts(count),
        replies:replies(count),
        liked_posts:post_likes(count),
        useful_posts:post_useful(count)
      `)
      .eq('id', id)
      .single();

    if (error) {
      return res.status(404).json({ message: '用户不存在' });
    }

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      vitality: user.vitality,
      bio: user.bio,
      is_admin: user.is_admin,
      is_main_admin: user.is_main_admin,
      followers_count: user.followers[0]?.count || 0,
      following_count: user.following[0]?.count || 0,
      posts_count: user.posts[0]?.count || 0,
      replies_count: user.replies[0]?.count || 0,
      likes_received_count: user.liked_posts[0]?.count || 0,
      useful_received_count: user.useful_posts[0]?.count || 0,
      created_at: user.created_at
    });
  } catch (error) {
    res.status(500).json({ message: '获取用户信息失败' });
  }
});

app.get('/api/users/:id/posts', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: posts, error } = await supabase
      .from('posts')
      .select(`
        id, 
        title, 
        content, 
        created_at, 
        likes_count, 
        replies_count,
        views_count
      `)
      .eq('author_id', id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: '获取用户帖子失败' });
  }
});

app.get('/api/users/:id/replies', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: replies, error } = await supabase
      .from('replies')
      .select(`
        id, 
        content, 
        created_at, 
        likes_count,
        post:posts(title)
      `)
      .eq('author_id', id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    // 格式化回复，添加帖子标题和内容预览
    const formattedReplies = replies.map(reply => ({
      id: reply.id,
      content: reply.content,
      content_preview: getPreview(reply.content, 100),
      created_at: reply.created_at,
      likes_count: reply.likes_count,
      post_title: reply.post.title
    }));

    res.json(formattedReplies);
  } catch (error) {
    res.status(500).json({ message: '获取用户回复失败' });
  }
});

app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ message: '不能关注自己' });
    }

    // 检查是否已关注
    const { data: existingFollow, error: followError } = await supabase
      .from('user_follows')
      .select('id')
      .eq('follower_id', req.user.id)
      .eq('followed_id', id)
      .single();

    if (existingFollow) {
      return res.status(400).json({ message: '已关注此用户' });
    }

    // 添加关注记录
    const { error: insertError } = await supabase
      .from('user_follows')
      .insert([{ follower_id: req.user.id, followed_id: id }]);

    if (insertError) {
      return res.status(500).json({ message: insertError.message });
    }

    // 增加被关注者活力值
    await updateVitality(id, 5);

    res.json({ message: '关注成功' });
  } catch (error) {
    res.status(500).json({ message: '关注失败' });
  }
});

app.post('/api/users/:id/unfollow', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 删除关注记录
    const { error } = await supabase
      .from('user_follows')
      .delete()
      .eq('follower_id', req.user.id)
      .eq('followed_id', id);

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    // 减少被关注者活力值
    await updateVitality(id, -5);

    res.json({ message: '取消关注成功' });
  } catch (error) {
    res.status(500).json({ message: '取消关注失败' });
  }
});

// 私信相关路由
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
  try {
    // 获取用户的所有对话
    const { data: conversations, error } = await supabase.rpc('get_user_conversations', { user_id: req.user.id });

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(conversations);
  } catch (error) {
    res.status(500).json({ message: '获取私信列表失败' });
  }
});

app.get('/api/messages/conversation/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 检查用户是否参与此对话
    const { data: conversationCheck, error: checkError } = await supabase
      .from('conversations')
      .select('id')
      .eq('id', id)
      .or(`user1_id.eq.${req.user.id},user2_id.eq.${req.user.id}`)
      .single();

    if (checkError || !conversationCheck) {
      return res.status(404).json({ message: '对话不存在或无权访问' });
    }

    // 获取对话详情和消息
    const { data: messages, error: messagesError } = await supabase
      .from('messages')
      .select(`
        *,
        sender:users(username)
      `)
      .eq('conversation_id', id)
      .order('sent_at', { ascending: true });

    if (messagesError) {
      return res.status(500).json({ message: messagesError.message });
    }

    // 标记消息为已读
    await supabase
      .from('messages')
      .update({ is_read: true })
      .eq('conversation_id', id)
      .eq('recipient_id', req.user.id)
      .eq('is_read', false);

    res.json({
      id: id,
      messages
    });
  } catch (error) {
    res.status(500).json({ message: '获取私信详情失败' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { conversation_id, content } = req.body;

    if (!content) {
      return res.status(400).json({ message: '消息内容不能为空' });
    }

    // 检查用户是否参与此对话
    const { data: conversation, error: convError } = await supabase
      .from('conversations')
      .select('user1_id, user2_id')
      .eq('id', conversation_id)
      .single();

    if (convError || !conversation) {
      return res.status(404).json({ message: '对话不存在' });
    }

    const recipientId = conversation.user1_id === req.user.id ? conversation.user2_id : conversation.user1_id;

    // 发送消息
    const { data: message, error: msgError } = await supabase
      .from('messages')
      .insert([{
        conversation_id,
        sender_id: req.user.id,
        recipient_id: recipientId,
        content
      }])
      .select()
      .single();

    if (msgError) {
      return res.status(500).json({ message: msgError.message });
    }

    res.json(message);
  } catch (error) {
    res.status(500).json({ message: '发送消息失败' });
  }
});

app.post('/api/messages/start', authenticateToken, async (req, res) => {
  try {
    const { recipient_username } = req.body;

    // 查找接收者
    const { data: recipient, error: userError } = await supabase
      .from('users')
      .select('id')
      .eq('username', recipient_username)
      .single();

    if (userError || !recipient) {
      return res.status(404).json({ message: '用户不存在' });
    }

    if (recipient.id === req.user.id) {
      return res.status(400).json({ message: '不能给自己发送私信' });
    }

    // 检查是否已有对话
    const { data: existingConv, error: existingError } = await supabase
      .from('conversations')
      .select('id')
      .or(
        `and(user1_id.eq.${req.user.id},user2_id.eq.${recipient.id}),` +
        `and(user1_id.eq.${recipient.id},user2_id.eq.${req.user.id})`
      )
      .single();

    if (existingConv) {
      return res.json({ conversation_id: existingConv.id });
    }

    // 创建新对话
    const { data: conversation, error: convCreateError } = await supabase
      .from('conversations')
      .insert([{
        user1_id: req.user.id,
        user2_id: recipient.id
      }])
      .select()
      .single();

    if (convCreateError) {
      return res.status(500).json({ message: convCreateError.message });
    }

    res.json({ conversation_id: conversation.id });
  } catch (error) {
    res.status(500).json({ message: '开始对话失败' });
  }
});

// 工单相关路由
app.get('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const { data: tickets, error } = await supabase
      .from('tickets')
      .select(`
        id, 
        title, 
        content, 
        status, 
        created_at,
        author:users(username)
      `)
      .eq('author_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(tickets);
  } catch (error) {
    res.status(500).json({ message: '获取工单列表失败' });
  }
});

app.post('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: '标题和内容不能为空' });
    }

    const { data: ticket, error } = await supabase
      .from('tickets')
      .insert([{
        title,
        content,
        author_id: req.user.id,
        status: 'open'
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(ticket);
  } catch (error) {
    res.status(500).json({ message: '提交工单失败' });
  }
});

// 管理员相关路由
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { search = '' } = req.query;

    let query = supabase
      .from('users')
      .select(`
        id, 
        username, 
        email, 
        vitality, 
        is_admin, 
        is_main_admin,
        created_at
      `)
      .order('created_at', { ascending: false });

    if (search) {
      query = query.ilike('username', `%${search}%`);
    }

    const { data: users, error } = await query;

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: '获取用户列表失败' });
  }
});

app.get('/api/admin/posts', adminAuth, async (req, res) => {
  try {
    const { search = '' } = req.query;

    let query = supabase
      .from('posts')
      .select(`
        id, 
        title, 
        content, 
        created_at, 
        category,
        is_important,
        author:users(username)
      `)
      .order('created_at', { ascending: false });

    if (search) {
      query = query.ilike('title', `%${search}%`);
    }

    const { data: posts, error } = await query;

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: '获取帖子列表失败' });
  }
});

app.get('/api/admin/tickets', adminAuth, async (req, res) => {
  try {
    const { data: tickets, error } = await supabase
      .from('tickets')
      .select(`
        id, 
        title, 
        content, 
        status, 
        created_at,
        author:users(username)
      `)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json(tickets);
  } catch (error) {
    res.status(500).json({ message: '获取工单列表失败' });
  }
});

app.post('/api/admin/make-admin', mainAdminAuth, async (req, res) => {
  try {
    const { username } = req.body;

    // 查找用户
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('id, is_main_admin')
      .eq('username', username)
      .single();

    if (userError || !user) {
      return res.status(404).json({ message: '用户不存在' });
    }

    if (user.is_main_admin) {
      return res.status(400).json({ message: '不能修改主管理员' });
    }

    // 设置为管理员
    const { error: updateError } = await supabase
      .from('users')
      .update({ is_admin: true })
      .eq('id', user.id);

    if (updateError) {
      return res.status(500).json({ message: updateError.message });
    }

    res.json({ message: '设置管理员成功' });
  } catch (error) {
    res.status(500).json({ message: '设置管理员失败' });
  }
});

app.post('/api/admin/users/:id/ban', mainAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({ message: '请提供封禁理由' });
    }

    // 检查用户是否存在且不是主管理员
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('is_main_admin')
      .eq('id', id)
      .single();

    if (userError || !user) {
      return res.status(404).json({ message: '用户不存在' });
    }

    if (user.is_main_admin) {
      return res.status(400).json({ message: '不能封禁主管理员' });
    }

    // 封禁用户
    const { error: updateError } = await supabase
      .from('users')
      .update({ is_banned: true })
      .eq('id', id);

    if (updateError) {
      return res.status(500).json({ message: updateError.message });
    }

    res.json({ message: '用户已封禁' });
  } catch (error) {
    res.status(500).json({ message: '封禁用户失败' });
  }
});

app.delete('/api/admin/posts/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // 删除帖子
    const { error } = await supabase
      .from('posts')
      .delete()
      .eq('id', id);

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json({ message: '帖子已删除' });
  } catch (error) {
    res.status(500).json({ message: '删除帖子失败' });
  }
});

app.delete('/api/admin/tickets/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // 删除工单
    const { error } = await supabase
      .from('tickets')
      .delete()
      .eq('id', id);

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json({ message: '工单已删除' });
  } catch (error) {
    res.status(500).json({ message: '删除工单失败' });
  }
});

app.post('/api/admin/tickets/:id/:action', adminAuth, async (req, res) => {
  try {
    const { id, action } = req.params;

    let status;
    switch (action) {
      case 'resolve':
        status = 'resolved';
        break;
      case 'pending':
        status = 'pending';
        break;
      case 'close':
        status = 'closed';
        break;
      default:
        return res.status(400).json({ message: '无效的操作' });
    }

    // 更新工单状态
    const { error } = await supabase
      .from('tickets')
      .update({ status })
      .eq('id', id);

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json({ message: '工单状态已更新' });
  } catch (error) {
    res.status(500).json({ message: '更新工单状态失败' });
  }
});

// 活力值每周减少任务（简化版，实际部署时需要使用定时任务）
app.post('/api/admin/reduce-vitality', mainAdminAuth, async (req, res) => {
  try {
    // 获取所有非管理员用户
    const { data: users, error } = await supabase
      .from('users')
      .select('id, vitality')
      .is('is_admin', false)
      .is('is_main_admin', false);

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    for (const user of users) {
      if (user.vitality > 0) {
        await updateVitality(user.id, -1);
      }
    }

    res.json({ message: '活力值已更新' });
  } catch (error) {
    res.status(500).json({ message: '更新活力值失败' });
  }
});

// 根路由
app.get('/', (req, res) => {
  res.json({ message: '论坛API服务' });
});

// 404处理
app.use((req, res) => {
  res.status(404).json({ message: '接口不存在' });
});

// 错误处理中间件
app.use((error, req, res, next) => {
  console.error('服务器错误:', error);
  res.status(500).json({ message: '服务器内部错误' });
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`服务器运行在端口 ${PORT}`);
});

module.exports = app;