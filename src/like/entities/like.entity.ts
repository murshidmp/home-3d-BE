import { Entity, PrimaryGeneratedColumn, ManyToOne, Column } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Post } from '../../post/entities/post.entity';

@Entity('likes')
export class Like {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.likes, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Post, (post) => post.likes, { onDelete: 'CASCADE' })
  post: Post;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
